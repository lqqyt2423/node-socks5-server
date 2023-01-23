"use strict";

const socks5 = require("..");
const ipv4 = require("../utils/ipv4");

const server = socks5.createServer({
  logger: {
    // debug: function() {}, /* Disable debug messages */
    debug: console.debug,
    info: console.info,
    warn: console.warn,
    error: console.error,
  },
  // localAddress: "192.168.0.100", /* Local Interface address */
});

server.listen(1080);
