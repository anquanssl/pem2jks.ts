import OutputStream2 from '../Stream/OutputStream2';
import InputStream from '../Stream/InputStream';

class DerValue {
  public static tag_ObjectId: number = 0x06;
  public static tag_Sequence: number = 0x30;
  public static tag_OctetString: number = 0x04;
  public static tag_Integer: number = 0x02;

  public tag: number | null = null;
  public length: number = 0;
  public data: InputStream | null = null;
  public buffer: Buffer | null = null;

  constructor(inputStream: InputStream) {
    this.buffer = inputStream.buffer.slice(inputStream.offset);
    this.init(inputStream);
  }

  private init(inputStream: InputStream): void {
    this.tag = inputStream.readByte();
    const lenByte = inputStream.buffer.readUInt8(inputStream.offset);
    this.length = DerValue.getLength(inputStream);

    if (this.length === -1) {
      const readLen = inputStream.available();
      let offset = 2;
      // Assuming OutputStream2 class is defined, replace with your implementation
      const indefData = new OutputStream2(Buffer.alloc(readLen + offset));
      indefData.write(this.tag);
      indefData.write(lenByte);
      indefData.write(inputStream.read(readLen));

      throw new Error('Length is not defined. The DerIndefLenConverter.convert() has not been implemented yet');
    }

    this.data = new InputStream(inputStream.read(this.length));
  }

  /** Returns true if the CONSTRUCTED bit is set in the type tag. */
  public isConstructed(constructedTag?: number): boolean {
    const constructed = ((<number> this.tag & 0x020) == 0x020);

    if (!constructed) {
      return false;
    }

    if (constructedTag) {
      return ((<number>this.tag & 0x01f) == constructedTag);
    } else {
      return true;
    }
  }

  public static getLength(inputStream: InputStream): number {
    let len = inputStream.readByte();

    if ((len & 0x080) === 0x00) {
      return len;
    }

    let tmp = len & 0x07f;

    /*
     * NOTE:  tmp == 0 indicates indefinite length encoded data.
     * tmp > 4 indicates more than 4Gb of data.
     */
    if (tmp === 0) {
      return -1;
    }

    if (tmp < 0) {
      throw new Error('Incorrect DER encoding');
    } else if (tmp > 4) {
      throw new Error('DER length too big');
    }

    let value = 0;

    for (value = 0; tmp > 0; tmp--) {
      value <<= 8;
      value += 0x0ff & inputStream.readByte();
    }

    if (value < 0) {
      throw new Error('Invalid length byte');
    }

    return value;
  }

  public getBigInteger(): bigint | number {
    const inputStream = <InputStream>this.data;

    if (inputStream.readByte() !== DerValue.tag_Integer) {
      throw new Error('DER input, Integer tag error');
    }
    const length = DerValue.getLength(inputStream);

    if (length <= 1) {
      return inputStream.readByte();
    } else if (length === 2) {
      return inputStream.readShort();
    } else if (length <= 4) {
      return inputStream.readInt();
    } else {
      return inputStream.readLong();
    }
  }

  public getOctetString(): Buffer {
    if (this.tag !== DerValue.tag_OctetString && !this.isConstructed(DerValue.tag_OctetString)) {
      throw new Error('DerValue.getOctetString, not an Octet String: ' + this.tag);
    }

    const stream = new InputStream(<Buffer>this.buffer);

    let bytes: Buffer = Buffer.from([]);

    while (stream.available()) {
      const tag = stream.readByte();

      if (tag !== DerValue.tag_OctetString) {
        throw new Error('DER input not an octet string: ' + tag);
      }

      const length = DerValue.getLength(stream);
      const data = stream.read(length);

      bytes = Buffer.concat([bytes, data]);
    }

    return bytes;
  }

  public getDerValue(): DerValue {
    return new DerValue(this.data as InputStream);
  }
}

export default DerValue;
