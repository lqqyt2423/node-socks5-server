# node-socks5-server

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

## feature

- "No Auth" mode
- User/Password authentication
- Support for the CONNECT command

## example

Below is a simple example of usage. Go examples folder see more.

```javascript
const socks5 = require('node-socks5-server');

const server = socks5.createServer();
server.listen(1080, 'localhost');
```

## test

```bash
curl http://www.baidu.com/ --socks5 localhost:1080
curl http://www.baidu.com/ --socks5-hostname localhost:1080
curl http://www.baidu.com/ --socks5 user:password@localhost:1080
```

## todo

- ipv6 support
- domain support

## thanks

- [socks](https://zh.wikipedia.org/wiki/SOCKS)
- [rfc1928](https://tools.ietf.org/html/rfc1928)
- [rfc1929](https://tools.ietf.org/html/rfc1929)
- [go-socks](https://github.com/armon/go-socks5)
