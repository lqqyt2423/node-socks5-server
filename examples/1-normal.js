'use strict';

const socks5 = require('..');

const server = socks5.createServer();
server.listen(1080, 'localhost');
