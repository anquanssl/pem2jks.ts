import { Buffer } from 'buffer';

class OutputStream {
  private buffer: Buffer;
  private offset: number;

  constructor() {
    this.buffer = Buffer.alloc(0);
    this.offset = 0;
  }

  writeInt(value: number): void {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value, 0);
    this.write(buffer);
  }

  writeUTF(str: string): void {
    const length = Buffer.from(str).length;
    const lengthBuffer = Buffer.alloc(2);
    lengthBuffer.writeUInt16BE(length, 0);

    this.write(lengthBuffer);
    this.write(Buffer.from(str));
  }

  /**
   * 写入Buffer
   * @param data
   */
  write(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
    this.offset += data.byteLength;
  }

	shift(bytes: number): number {
		this.write(Buffer.alloc(bytes));
		return this.offset;
	}

  writeLong(value: bigint | number): void {
    const longBuffer = Buffer.alloc(8);

    if (typeof value !== 'bigint') {
      value = BigInt(value);
    }
    longBuffer.writeBigUInt64BE(<any> value, 0);

    this.write(longBuffer);
  }

  writeByte(value: number): void {
    const buffer = Buffer.alloc(1);
    buffer.writeUInt8(value, 0);
    this.write(buffer);
  }

  writeShort(value: number): void {
    const buffer = Buffer.alloc(2);
    buffer.writeUInt16BE(value, 0);
    this.write(buffer);
  }

  /**
   * 获取Buffer
   *
   * @returns {Buffer}
   */
  getBuffer(): Buffer {
    return this.buffer;
  }

  /**
   * 获取一个Buffer的拷贝
   *
   * @returns {Buffer}
   */
  getBufferCopy(): Buffer {
    return Buffer.concat([this.getBuffer(),]);
  }
}

export default OutputStream;
