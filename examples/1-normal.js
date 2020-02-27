'use strict';

const socks5 = require('..');

const server = socks5.createServer();

// ipv4
server.listen(1080, 'localhost');

// ipv6
// server.listen(1080);
