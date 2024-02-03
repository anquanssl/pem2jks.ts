import { Buffer } from "buffer";

export type Salt = 'Mighty Aphrodite';

export default class PasswordDigest {
  buffer: Buffer;
  password: string;
  salt: Salt = 'Mighty Aphrodite';

  constructor(buffer: Buffer, password: string) {
    this.buffer = Buffer.alloc(0);
    this.password = password;
    this.getPreKeyedHash();
    this.update(buffer);
  }

  update(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  digist(): Promise<ArrayBuffer> {
    return new Promise(async (resolve, reject) => {
      return crypto.subtle.digest("SHA-1", this.buffer).then((hash) => {
        return resolve(hash);
      });
    });
  }

	getPreKeyedHash() {
    const passwdBytes = Buffer.alloc(this.password.length * 2);
    for (let i = 0, j = 0; i < this.password.length; i++) {
      passwdBytes[j++] = this.password[i].charCodeAt(0) >> 8;
      passwdBytes[j++] = this.password[i].charCodeAt(0);
    }
    this.update(passwdBytes);
    this.update(Buffer.from(this.salt));
	}
};
