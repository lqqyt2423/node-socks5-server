function numberToBuffer(num, len = 2, byteOrder = 0) {
  if (len < 1) {
    throw Error('len must be greater than 0');
  }

  const buf = Buffer.alloc(len);

  if (byteOrder === 0) {
    buf.writeUIntBE(num, 0, len);
  } else {
    buf.writeUIntLE(num, 0, len);
  }

  return buf;
}
exports.numberToBuffer = numberToBuffer;
