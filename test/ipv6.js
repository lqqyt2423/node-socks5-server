'use strict';

const assert = require('assert');
const ipv6 = require('../utils/ipv6');

assert.deepEqual(ipv6.toBufArr('::'), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
assert.deepEqual(ipv6.toBufArr('::1'), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
assert.deepEqual(
  ipv6.toBufArr('2001:0db8:85a3:08d3:1319:8a2e:0370:7344'),
  [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44]
);
assert.deepEqual(
  ipv6.toBufArr('2001:DB8:2de:0:0:0:0:e13'),
  [0x20, 0x01, 0x0D, 0xB8, 0x02, 0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x13]
);
assert.deepEqual(
  ipv6.toBufArr('2001:DB8:2de::e13'),
  [0x20, 0x01, 0x0D, 0xB8, 0x02, 0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x13]
);
assert.deepEqual(ipv6.toBufArr('::ffff:1.2.3.4'), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4]);

assert.deepEqual(
  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  ipv6.toBufArr(ipv6.toStr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
);
assert.deepEqual(
  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
  ipv6.toBufArr(ipv6.toStr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
);
assert.deepEqual(
  [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44],
  ipv6.toBufArr(ipv6.toStr([0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44]))
);
assert.deepEqual(
  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4],
  ipv6.toBufArr(ipv6.toStr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4]))
);

console.log('ipv6.js all test passed!');
