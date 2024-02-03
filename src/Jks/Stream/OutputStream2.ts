import { Buffer } from 'buffer';

class OutputStream2 {
  buffer: Buffer;
  offset: number;

  constructor(buffer: ArrayBuffer) {
		this.buffer = Buffer.from(buffer);
		this.offset = 0;
	}

	write(data: string | number | any[] | Buffer | Uint8Array) {
		if (typeof data === 'number') {
			this.buffer.writeUInt8(data, this.offset);
			this.offset++;
		} else if (Buffer.isBuffer(data)) {
			this.buffer = Buffer.concat([ this.buffer.slice(0, this.offset), data ]);
			this.offset += data.length;
		}
	}
}

export default OutputStream2;
