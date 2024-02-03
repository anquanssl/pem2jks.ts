import { Buffer } from 'buffer';
import PKCS8Key from './PKCS8Key';
import DerValue from './DerValue';
import InputStream from '../Stream/InputStream';

class KeyProtector {
  private passwdBytes: Buffer;

  public static SALT_LEN: number = 20;
  public static DIGEST_ALG: string = "SHA-1";
  public static DIGEST_LEN: number = 20;
  public static KEY_PROTECTOR_OID: `1.3.6.1.4.1.42.2.17.1.1` = '1.3.6.1.4.1.42.2.17.1.1';

  constructor(password: string) {
    this.passwdBytes = Buffer.alloc(password.length * 2);

    for (let i = 0, j = 0; i < password.length; i++) {
      this.passwdBytes[j++] = password[i].charCodeAt(0) >> 8;
      this.passwdBytes[j++] = password[i].charCodeAt(0);
    }
  }

  private resetDigest() {
  }

  public async recover(encryptedPrivateKeyInfo: any): Promise<any> {
    return new Promise(async (resolve, reject) => {
      let digest: Buffer;
      let numRounds: number;
      let encrKeyLen: number; // the length of the encrypted key

      const algId = encryptedPrivateKeyInfo.getAlgorithm();
      if (algId !== KeyProtector.KEY_PROTECTOR_OID) {
        throw new Error("Unsupported key protection algorithm");
      }
      let protectedKey = encryptedPrivateKeyInfo.getEncryptedData();
      const salt = protectedKey.slice(0, KeyProtector.SALT_LEN);
      encrKeyLen = protectedKey.length - KeyProtector.SALT_LEN - KeyProtector.DIGEST_LEN;
      numRounds = Math.floor(encrKeyLen / KeyProtector.DIGEST_LEN);

      if ((encrKeyLen % KeyProtector.DIGEST_LEN) !== 0) {
        numRounds++;
      }

      const encrKey = protectedKey.slice(
        KeyProtector.SALT_LEN,
        encrKeyLen + KeyProtector.SALT_LEN
      );

      let xorKey = Buffer.alloc(encrKey.length);

      for (
        let i = 0, xorOffset = 0;
        i < numRounds;
        i++, xorOffset += KeyProtector.DIGEST_LEN
      ) {
        const hash = await crypto.subtle.digest("SHA-1", Buffer.concat([this.passwdBytes, salt,]));
        digest = Buffer.from(hash);
        this.resetDigest();

        if (i < numRounds - 1) {
          xorKey = Buffer.concat([
            xorKey.slice(0, xorOffset),
            digest
          ]);
        } else {
          xorKey = Buffer.concat([
            xorKey.slice(0, xorOffset),
            digest.slice(0, encrKey.length - xorOffset)
          ]);
        }
      }

      const plainKey = Buffer.alloc(encrKey.length);
      for (let i = 0; i < plainKey.length; i++) {
        plainKey[i] = encrKey[i] ^ xorKey[i];
      }

      const hash = await crypto.subtle.digest("SHA-1", Buffer.concat([this.passwdBytes, plainKey,]));
      digest = Buffer.from(hash);
      this.resetDigest();

      for (let i = 0; i < digest.length; i++) {
        if (digest[i] !== protectedKey[KeyProtector.SALT_LEN + encrKeyLen + i]) {
          throw new Error("Cannot recover key");
        }
      }

      return resolve(PKCS8Key.parseKey(
        new DerValue(
          new InputStream(plainKey)
        )
      ));
    });
  }
}

export default KeyProtector;
