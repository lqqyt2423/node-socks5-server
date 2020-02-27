'use strict';

const net = require('net');
const dns = require('dns');
const util = require('util');
const ipv6 = require('./ipv6');

class SocketHandler {
  constructor(socket, options = {}) {
    this.socket = socket;
    this.logger = options.logger || console;

    if (options.userPassAuthFn) {
      if (typeof options.userPassAuthFn !== 'function') throw new TypeError('userPassAuthFn should be function');
      this.userPassAuthFn = options.userPassAuthFn;
    }

    this.init();
  }

  init() {
    this.socket.on('error', err => {
      this.logger.error(err);
      if (!this.socket.destroyed) this.socket.destroy();
    });

    this.socket.on('timeout', () => {
      this.logger.warn('socket timeout');
      this.socket.end();
    });
  }

  consume() {
    return new Promise(resolve => {
      this.socket.once('data', resolve);
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
      this.logger.error('Unsupported auth version: %d', data[0]);
      this.socket.end();
      return true;
    }

    const ulen = data[1];
    const uname = data.toString('ascii', 2, 2+ulen);
    const plen = data[2+ulen];
    const passwd = data.toString('ascii', 2+ulen+1, 2+ulen+1+plen);

    this.logger.debug('uname: %s, passwd: %s', uname, passwd);

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
      this.logger.error('Unsupported SOCKS version: %d', data[0]);
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
    if (methods.includes(0x02) && this.userPassAuthFn) {
      this.socket.write(Buffer.from([0x05, 0x02]));
      return await this.authUserPass();
    }
    else if (methods.includes(0x00)) {
      this.socket.write(Buffer.from([0x05, 0x00]));
    }
    else {
      this.logger.error('auth methods not support');
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

    if (address.family === 'IPv4') {
      data.push(0x01);
      for (const str of address.address.split('.')) {
        data.push(Number(str));
      }
    }
    else if (address.family === 'IPv6') {
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
      this.logger.error('Unsupported SOCKS version: %d', data[0]);
      return this.socket.end();
    }

    // o  CONNECT X'01'
    // o  BIND X'02'
    // o  UDP ASSOCIATE X'03'
    if (data[1] !== 0x01) {
      this.reply(0x07);
      return this.socket.end();
    }

    if (data[2] !== 0x00) this.logger.warn('RESERVED should be 0x00');

    let dstHost, dstPort;
    switch (data[3]) {
    case 0x01: // ipv4
      dstHost = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
      dstPort = (data[8] << 8) | data[9];
      break;
    case 0x03: // domain
    {
      const domainLen = data[4];
      const domain = data.toString('ascii', 5, 5+domainLen);
      try {
        const ips = await util.promisify(dns.resolve4)(domain);
        dstHost = ips[0];
      } catch (err) {
        this.logger.error(err);
        this.reply(0x04);
        return this.socket.end();
      }
      dstPort = (data[5+domainLen] << 8) | data[5+domainLen+1];
      break;
    }
    case 0x04: // ipv6
    {
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
    const proxy = net.createConnection(dstPort, dstHost);

    proxy.on('error', (err) => {
      this.logger.error(err);
      if (!replyed) {
        // X'05' Connection refused
        this.reply(0x05);
      }
      if (!proxy.destroyed) proxy.destroy();
      this.socket.end();
    });

    proxy.on('timeout', () => {
      this.logger.warn('proxy timeout');
      if (!replyed) {
        // X'05' Connection refused
        this.reply(0x05);
      }
      proxy.end();
      this.socket.end();
    });

    proxy.once('connect', () => {
      this.reply(0x00, proxy.address());
      replyed = true;

      this.socket.pipe(proxy);
      proxy.pipe(this.socket);
    });
  }

  async handle() {
    const finished = await this.authentication();
    if (finished) return;

    this.request();
  }
}

function createServer(options = {}) {
  const server = net.createServer(socket => {
    new SocketHandler(socket, options).handle();
  });
  return server;
}

exports.createServer = createServer;
