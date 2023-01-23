"use strict";

const net = require("net");
const { Resolver } = require("node:dns").promises;
const util = require("util");
const ipv4 = require("./utils/ipv4");
const ipv6 = require("./utils/ipv6");
const buf = require("./utils/buf");
const udp = require("dgram");

class SocketHandler {
  constructor(socket, options = {}) {
    this.socket = socket;
    this.logger = options.logger || console;
    this.port = options.port;
    this.localAddress = options.localAddress;
    this.dns = options.dns;

    if (options.userPassAuthFn) {
      if (typeof options.userPassAuthFn !== "function") throw new TypeError("userPassAuthFn should be function");
      this.userPassAuthFn = options.userPassAuthFn;
    }

    this.init();
  }

  init() {
    this.socket.on("error", (err) => {
      this.logger.error(err);
      if (!this.socket.destroyed) {
        return this.socket.destroy();
      }
    });

    this.socket.on("timeout", () => {
      this.logger.warn("socket timeout");
      this.socket.end();
    });
  }

  consume() {
    return new Promise((resolve) => {
      this.socket.once("data", resolve);
    });
  }

  //  +----+------+----------+------+----------+
  //  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
  //  +----+------+----------+------+----------+
  //  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
  //  +----+------+----------+------+----------+

  async authUserPass() {
    const data = await this.consume();
    if (data[0] != 0x01) {
      this.logger.error("Unsupported auth version: %d", data[0]);
      this.socket.end();
      return true;
    }

    const ulen = data[1];
    const uname = data.toString("ascii", 2, 2 + ulen);
    const plen = data[2 + ulen];
    const passwd = data.toString("ascii", 2 + ulen + 1, 2 + ulen + 1 + plen);

    this.logger.debug("uname: %s, passwd: %s", uname, passwd);

    if (this.userPassAuthFn(uname, passwd)) {
      this.socket.write(Buffer.from([0x01, 0x00]));
    } else {
      this.socket.end(Buffer.from([0x01, 0x01]));
      return true;
    }
  }

  //   +----+----------+----------+
  //   |VER | NMETHODS | METHODS  |
  //   +----+----------+----------+
  //   | 1  |    1     | 1 to 255 |
  //   +----+----------+----------+

  async authentication() {
    const data = await this.consume();
    if (data[0] !== 0x05) {
      this.logger.error("Unsupported SOCKS version: %d", data[0]);
      this.socket.end();
      return true;
    }

    // o  X'00' NO AUTHENTICATION REQUIRED
    // o  X'01' GSSAPI
    // o  X'02' USERNAME/PASSWORD
    // o  X'03' to X'7F' IANA ASSIGNED
    // o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    // o  X'FF' NO ACCEPTABLE METHODS
    const nmethods = data[1];
    const methods = data.slice(2, 2 + nmethods);
    // only support 0x00 0x02
    if ((methods.includes(0x00) || methods.includes(0x02)) && this.userPassAuthFn) {
      this.socket.write(Buffer.from([0x05, 0x02]));
      return await this.authUserPass();
    } else if (methods.includes(0x00)) {
      this.socket.write(Buffer.from([0x05, 0x00]));
    } else {
      this.logger.error("auth methods not support");
      this.socket.end(Buffer.from([0x05, 0xff]));
      return true;
    }
  }

  //   +----+-----+-------+------+----------+----------+
  //   |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  //   +----+-----+-------+------+----------+----------+
  //   | 1  |  1  | X'00' |  1   | Variable |    2     |
  //   +----+-----+-------+------+----------+----------+

  //   o  X'00' succeeded
  //   o  X'01' general SOCKS server failure
  //   o  X'02' connection not allowed by ruleset
  //   o  X'03' Network unreachable
  //   o  X'04' Host unreachable
  //   o  X'05' Connection refused
  //   o  X'06' TTL expired
  //   o  X'07' Command not supported
  //   o  X'08' Address type not supported
  //   o  X'09' to X'FF' unassigned

  reply(rep, address) {
    const data = [0x05, rep, 0x00];

    if (!address) {
      this.socket.write(Buffer.from(data.concat([0x01, 0, 0, 0, 0, 0, 0])));
      return;
    }

    this.logger.debug(address);

    if (address.family === "IPv4") {
      data.push(0x01);
      for (const str of address.address.split(".")) {
        data.push(Number(str));
      }
    } else if (address.family === "IPv6") {
      data.push(0x04);
      const ipv6BufArr = ipv6.toBufArr(address.address);
      for (const byte of ipv6BufArr) {
        data.push(byte);
      }
    }

    data.push(address.port >> 8);
    data.push(address.port & 0xff);

    this.socket.write(Buffer.from(data));
  }

  async request() {
    // Requests

    //   +----+-----+-------+------+----------+----------+
    //   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    //   +----+-----+-------+------+----------+----------+
    //   | 1  |  1  | X'00' |  1   | Variable |    2     |
    //   +----+-----+-------+------+----------+----------+

    const data = await this.consume();
    if (data[0] != 0x05) {
      this.logger.error("Unsupported SOCKS version: %d", data[0]);
      return this.socket.end();
    }

    // o  CONNECT X'01'
    // o  BIND X'02'
    // o  UDP ASSOCIATE X'03'
    if (data[1] == 0x01) {
      // CONNECT METHOD REQUEST
      if (data[2] !== 0x00) this.logger.warn("RESERVED should be 0x00");
      let dstHost, dstPort;
      switch (data[3]) {
        case 0x01: // ipv4
          dstHost = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
          dstPort = (data[8] << 8) | data[9];
          break;
        case 0x03: {
          // domain
          const domainLen = data[4];
          const domain = data.toString("ascii", 5, 5 + domainLen);
          try {
            const dnsResolver = new Resolver();
            if (this.dns && typeof this.dns === "string") {
              dnsResolver.setServers([this.dns]);
            } else if (this.dns && typeof this.dns === "object") {
              dnsResolver.setServers(this.dns);
            }
            if (this.localAddress) {
              dnsResolver.setLocalAddress(this.localAddress);
            }
            const ips = await dnsResolver.resolve4(domain);
            dstHost = ips[0];
          } catch (err) {
            //fix
            if (net.isIP(domain)) {
              dstHost = domain;
            } else {
              this.logger.error(err);
              this.reply(0x04);
              return this.socket.end();
            }
          }
          dstPort = (data[5 + domainLen] << 8) | data[5 + domainLen + 1];
          break;
        }
        case 0x04: {
          // ipv6
          const addrBuf = data.slice(4, 20);
          dstHost = ipv6.toStr(addrBuf);
          dstPort = (data[20] << 8) | data[21];
          break;
        }
        default:
          this.logger.error(`ATYP ${data[3]} not support`);
          this.reply(0x08);
          return this.socket.end();
      }
      let replyed = false;
      const proxy = net.createConnection({
        host: dstHost,
        port: dstPort,
        localAddress: this.localAddress ? this.localAddress : undefined,
      });
      proxy.on("error", (err) => {
        this.logger.error(err);
        if (!replyed) {
          // X'05' Connection refused
          this.reply(0x05);
        }
        if (!proxy.destroyed) proxy.destroy();
        this.socket.end();
      });

      proxy.on("timeout", () => {
        this.logger.warn("proxy timeout");
        if (!replyed) {
          // X'05' Connection refused
          this.reply(0x05);
        }
        proxy.end();
        this.socket.end();
      });

      proxy.once("connect", () => {
        this.reply(0x00, proxy.address());
        replyed = true;

        this.socket.pipe(proxy);
        proxy.pipe(this.socket);
      });
    } else if (data[1] == 0x02) {
      //BIND METHOD REQUEST
      this.logger.error("BIND METHOD REQUEST not support");
      this.reply(0x07);
      return this.socket.end();
    } else if (data[1] == 0x03) {
      //UDP ASSOCIATE METHOD REQUEST
      this.reply(0x00, { address: "0.0.0.0", family: "IPv4", port: this.port });
      return this.socket.end();
    } else {
      this.logger.error("Unsupported method: %d", data[1]);
      this.reply(0x07);
      return this.socket.end();
    }
  }

  async handle() {
    const finished = await this.authentication();
    if (finished) return;

    this.request();
  }
}

function createServer(options = {}) {
  const logger = options.logger || console;
  const udpServer = udp.createSocket("udp4");
  const server = net.createServer((socket) => {
    options.port = server.address().port;
    new SocketHandler(socket, options).handle();
  });
  server.on("listening", () => {
    logger.info("server listening", server.address().address, server.address().port);
    udpServer.on("error", (err) => {
      logger.error(`server error:\n${err.stack}`);
      udpServer.close();
    });
    udpServer.on("message", (msg, incoming_info) => {
      let buffer = Uint8Array.prototype.slice.call(msg);
      if (buffer.length < 10) {
        logger.warn("Buffer length is too short");
        return null;
      }
      if (buffer[0] !== 0x00 || buffer[1] !== 0x00) {
        logger.warn("Reserved field should be 0x00");
        return null;
      }
      const frag = buffer[2];
      if (frag !== 0x00) {
        logger.warn("Fragment should be 0x00");
        return null;
      }
      let host = null;
      let pos = 4;
      switch (buffer[3]) {
        case 0x01:
          host = ipv4.toString(buffer.slice(4, 8));
          pos = pos + 4;
          break;
        case 0x03:
          host = buffer.slice(5, 5 + buffer[4]).toString();
          pos = pos + 1 + buffer[4];
          break;
        case 0x04:
          host = ipv4.toString(buffer.slice(4, 20));
          pos = pos + 16;
          break;
        default:
          break;
      }
      let port = buffer.slice(pos, pos + 2).readUInt16BE(0);
      let data = buffer.slice(pos + 2);
      logger.debug("INCOMING UDP message from " + incoming_info.address + ":" + incoming_info.port + " FOR " + host + ":" + port);
      //parse end
      //send data to outcoming
      const outcoming = udp.createSocket({ type: "udp4", reuseAddr: true });
      if (options.localAddress) {
        outcoming.bind({
          address: options.localAddress,
          port: 0,
          exclusive: true,
        });
      }
      outcoming.send(data, port, host, (err) => {
        if (err) {
          logger.error(err);
          return;
        }
      });
      outcoming.on("message", (msg, outcoming_info) => {
        logger.debug("RESPONSE FROM HOST", outcoming_info, " TO ", incoming_info);
        let buffer = Uint8Array.prototype.slice.call(msg);
        logger.debug("PREPARE UDP PACKET FOR INCOMING", incoming_info);
        let atyp = 0x03;
        if (outcoming_info.family === "IPv4") {
          atyp = 0x01;
        } else if (outcoming_info.family === "IPv6") {
          atyp = 0x04;
          logger.error("IPv6 not supported yet");
          return;
        }
        let _host = atyp === 0x03 ? Buffer.from(outcoming_info.address) : outcoming_info.family === "IPv4" ? ipv4.toBuffer(outcoming_info.address) : ipv6.toBufArr(outcoming_info.address);
        let _port = buf.numberToBuffer(outcoming_info.port);
        let data = Buffer.from([0x00, 0x00, 0x00, atyp, ...(atyp === 0x03 ? [_host.length] : []), ..._host, ..._port, ...buffer]);
        udpServer.send(data, incoming_info.port, incoming_info.address, function (err) {
          outcoming.close();
          if (err) {
            logger.error(err);
            return;
          }
          logger.debug("UDP PACKET SENT TO INCOMING", incoming_info);
        });
      });
      outcoming.on("error", (err) => {
        logger.error(err);
      });
    });
    udpServer.on("listening", () => {
      const address = udpServer.address();
      logger.debug(`UDP listening ${address.address}:${address.port}`);
    });
    udpServer.bind(server.address().port);
  });
  server.on("error", (err) => {
    logger.error(err);
  });
  server.on("close", () => {
    if (udpServer) {
      udpServer.close();
    }
    logger.info(`SOCKS5 server closed`);
  });
  return server;
}

exports.createServer = createServer;
