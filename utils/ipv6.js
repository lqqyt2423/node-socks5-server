'use strict';

const net = require('net');
const assert = require('assert');

function toBufArr(addr) {
  const bufArr = new Array(16).fill(0);
  if (!net.isIPv6(addr)) return bufArr;

  let index = 0;
  let dColonIndex = -1;
  let ipv4Index = -1;
  let groupStr = '';

  for (let i = 0, len = addr.length; i < len; i++) {
    // 58 :
    if (addr.charCodeAt(i) === 58) {
      if (groupStr) {
        const byte2 = parseInt(groupStr, 16);
        bufArr[index++] = byte2 >> 8;
        bufArr[index++] = byte2 & 0xff;
        groupStr = '';
      }

      if (addr.charCodeAt(i + 1) === 58) {
        dColonIndex = index;
        i++;
      }
    }

    // 46 .
    else if (addr.charCodeAt(i) === 46) {
      if (ipv4Index === -1) ipv4Index = index;
      if (groupStr) {
        const byte1 = parseInt(groupStr);
        bufArr[index++] = byte1;
        groupStr = '';
      }
    } else {
      groupStr += addr[i];
    }
  }

  if (groupStr) {
    if (ipv4Index > -1) {
      const byte1 = parseInt(groupStr);
      bufArr[index++] = byte1;
    } else {
      const byte2 = parseInt(groupStr, 16);
      bufArr[index++] = byte2 >> 8;
      bufArr[index++] = byte2 & 0xff;
    }
    groupStr = '';
  }

  if (dColonIndex > -1) {
    const offset = 16 - index;
    for (let i = index - 1; i >= dColonIndex; i--) {
      bufArr[i + offset] = bufArr[i];
      bufArr[i] = 0x00;
    }
  }

  return bufArr;
}

function toStr(buf) {
  assert(buf.length === 16);

  const dwArr = [];
  for (let i = 0; i < 16; i += 2) {
    const dw = (buf[i] << 8) | buf[i + 1];
    dwArr.push(dw.toString(16));
  }
  return dwArr.join(':');
}

exports.toBufArr = toBufArr;
exports.toStr = toStr;
