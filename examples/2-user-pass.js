'use strict';

const socks5 = require('..');

const users = {
  'user': 'password',
  'admin': '123456',
};

const userPassAuthFn = (user, password) => {
  if (users[user] === password) return true;
  return false;
};

const server = socks5.createServer({
  userPassAuthFn,
});
server.listen(1080);
