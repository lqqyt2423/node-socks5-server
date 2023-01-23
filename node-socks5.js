#!/usr/bin/env node

"use strict";

const socks5 = require("./index");

const argv = process.argv.slice(2);

if (argv[0] === "-h" || argv[0] === "--help") {
  console.log("Socks5 server, default list port at 1080. You can use -p or --port to change listen port.");
  process.exit();
}

let port = 1080;
if (argv[0] === "-p" || argv[0] === "--port") {
  if (argv[1] && parseInt(argv[1]) > 0) {
    port = parseInt(argv[1]);
  }
}

const server = socks5.createServer();
server.listen(port, () => {
  console.log(`socks5 server listen at ${port}`);
});
