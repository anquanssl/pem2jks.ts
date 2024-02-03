import ObjectIdentifier from './ObjectIdentifier';
import DerValue from './DerValue';
import { Buffer } from 'buffer';

class PKCS8Key {
  /* The version for this key */
  public static version: number = 0;

  public static supportedTypes: { [key: string]: string } = {
    'rsa': '1.2.840.113549.1.1.1',
    'rsa-pss': '1.2.840.113549.1.1.10',
    'dsa': '1.2.840.10040.4.1',
    'ec': '1.2.840.10045.2.1',
    'x25519': '1.3.101.110',
    'x448': '1.3.101.111',
    'ed25519': '1.3.101.112',
    'ed448': '1.3.101.113',
    'dh': '1.2.840.113549.1.3.1',
  };

  /*
   * Construct PKCS#8 subject public key from a DER value.
   *
   * @param plainKey the DER-encoded SubjectPublicKeyInfo value
   */
  public static parseKey(plainKey: DerValue): string {
    if (plainKey.tag !== DerValue.tag_Sequence) {
      throw new Error('corrupt private key');
    }

    const parsedVersion = plainKey.getBigInteger();

    if (parsedVersion !== PKCS8Key.version) {
      throw new Error('version mismatch: (supported ' + PKCS8Key.version + ', parsed: ' + parsedVersion);
    }

    const seq0 = plainKey.getDerValue();
    const seq1 = plainKey.getDerValue();
    const algorithm = new ObjectIdentifier(seq0.data);

    if (
      PKCS8Key.supportedTypes['dsa'] === algorithm.toString() ||
      PKCS8Key.supportedTypes['ec'] === algorithm.toString()
    ) {
      return PKCS8Key.format(<Buffer>plainKey.buffer);
    }

    try {
      const octetString = seq1.getOctetString();

      return PKCS8Key.export(octetString);
    } catch (e) {
      const error = new Error('Something went wrong with algorithm ' + algorithm.toString() + '. For more details see \'error.context\'');
      // @ts-ignore
      error.context = e;

      throw error;
    }
  }

  public static export(key: Buffer): string {
    return this.format(key);
  }

  public static format(data: Buffer): string {
    const payload = data.toString('base64').match(/.{1,64}/g)?.join('\n');
    return '-----BEGIN PRIVATE KEY-----\n' +
      payload +
      '\n-----END PRIVATE KEY-----\n';
  }
}

export default PKCS8Key;
