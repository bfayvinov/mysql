var Buffer = require('safe-buffer').Buffer;

const getLengthCodedLength = function(length) {
  if (length < 251) return 1;
  if (length < 0x10000) return 3;
  if (length < 0x1000000) return 4;
  return 9;
};

module.exports = ClientAuthenticationPacket;
function ClientAuthenticationPacket(options) {
  options = options || {};

  this.clientFlags   = options.clientFlags;
  this.maxPacketSize = options.maxPacketSize;
  this.charsetNumber = options.charsetNumber;
  this.filler        = undefined;
  this.user          = options.user;
  this.scrambleBuff  = options.scrambleBuff;
  this.database      = options.database;
  this.protocol41    = options.protocol41;
  this.connectAttributes  = options.connectAttributes || null; 
}

ClientAuthenticationPacket.prototype.parse = function(parser) {
  if (this.protocol41) {
    this.clientFlags   = parser.parseUnsignedNumber(4);
    this.maxPacketSize = parser.parseUnsignedNumber(4);
    this.charsetNumber = parser.parseUnsignedNumber(1);
    this.filler        = parser.parseFiller(23);
    this.user          = parser.parseNullTerminatedString();
    this.scrambleBuff  = parser.parseLengthCodedBuffer();
    this.database      = parser.parseNullTerminatedString();
  } else {
    this.clientFlags   = parser.parseUnsignedNumber(2);
    this.maxPacketSize = parser.parseUnsignedNumber(3);
    this.user          = parser.parseNullTerminatedString();
    this.scrambleBuff  = parser.parseBuffer(8);
    this.database      = parser.parseLengthCodedBuffer();
  }
};

ClientAuthenticationPacket.prototype.write = function(writer) {
  if (this.protocol41) {
    writer.writeUnsignedNumber(4, this.clientFlags);
    writer.writeUnsignedNumber(4, this.maxPacketSize);
    writer.writeUnsignedNumber(1, this.charsetNumber);
    writer.writeFiller(23);
    writer.writeNullTerminatedString(this.user);
    writer.writeLengthCodedBuffer(this.scrambleBuff);
    writer.writeNullTerminatedString(this.database);

    const CLIENT_CONNECT_ATTRS = 0x00100000;

    if ((this.clientFlags & CLIENT_CONNECT_ATTRS) && this.connectAttributes) {
      const attributes = this.connectAttributes;
      const keys = Object.keys(attributes);
      let attrLen = 0;
      for (const key of keys) {
        const val = attributes[key];
        const keyLen = Buffer.byteLength(key);
        const valLen = Buffer.byteLength(val);
        attrLen += getLengthCodedLength(keyLen) + keyLen +
                   getLengthCodedLength(valLen) + valLen;
      }
      writer.writeLengthCodedNumber(attrLen);
      for (const key of keys) {
        writer.writeLengthCodedString(key);
        writer.writeLengthCodedString(attributes[key]);
      }
    }
  } else {
    writer.writeUnsignedNumber(2, this.clientFlags);
    writer.writeUnsignedNumber(3, this.maxPacketSize);
    writer.writeNullTerminatedString(this.user);
    writer.writeBuffer(this.scrambleBuff);
    if (this.database && this.database.length) {
      writer.writeFiller(1);
      writer.writeBuffer(Buffer.from(this.database));
    }
  }
};
