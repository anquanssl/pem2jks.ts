import { Buffer } from 'buffer';

class InputStream {
  public buffer: Buffer;
  public offset: number;

  constructor(buffer: Buffer) {
    this.buffer = Buffer.from(buffer);
    this.offset = 0;
  }

  public readInt(): number {
    return this.buffer.readUInt32BE(this.shift(4));
  }

  public readUTF(): string {
    const length = this.buffer.readUInt16BE(this.shift(2));
    return this.read(length).toString();
  }

  public read(length: number): Buffer {
    return this.buffer.slice(this.offset, this.shift(length) + length);
  }

  public readLong(): bigint | number {
    const value = this.read(8);
    if (typeof value.readBigUInt64BE === 'function') {
      return value.readBigUInt64BE();
    } else {
      const num = BigInt(value.readInt32BE());
      return num;
    }
  }

  public readByte(): number {
    return this.buffer.readUInt8(this.shift(1));
  }

  public readShort(): number {
    return this.read(2).readUInt16BE();
  }

  private shift(bytes: number): number {
    const offset = this.offset;
    this.offset += bytes;
    return offset;
  }

  public available(): number {
    return this.buffer.length - this.offset;
  }
}

export default InputStream;
