import { Buffer } from 'buffer';
// const jksJs = require('jks-js');
const pkijs = require('pkijs');
const ans1js = require('asn1js');
const asn1 = require('asn1.js');
import OutputStream from './Jks/Stream/OutputStream';
import PasswordDigest from './Jks/Encryption/PasswordDigist';
import ASN1 from '@lapo/asn1js';
import rsaPKCS from './Jks/PKCS/rsaPKCS';
import ecPKCS from './Jks/PKCS/ecPKCS';
import forge from 'node-forge';

export interface PEM { cert: string; key: string; };

export type JKS_MAGIC = 0xfeedfeed;
export type JKS_VERSION_1 = 0x01;
export type JKS_VERSION_2 = 0x02;
export type JKS_PRIVATE_KEY_TAG = 1;
export type JKS_TRUSTED_CERT_TAG = 2;

export const JKS_MAGIC = 0xfeedfeed;
export const JKS_VERSION_1 = 0x01;
export const JKS_VERSION_2 = 0x02;
export const JKS_PRIVATE_KEY_TAG = 1;
export const JKS_TRUSTED_CERT_TAG = 2;

export default class Jks {
  public cert!: string;
  public key!: string;
  public password!: string;
  public jks!: ArrayBuffer;
  private stream: OutputStream;

  constructor() {
    this.stream = new OutputStream();
  }

  /**
   * 从PEM初始化实例
   *
   * @param cert 证书PEM
   * @param key 私钥PEM
   * @param password 私钥密码，可不传
   * @returns {Jks}
   */
  static fromPEM(cert: string, key: string, password: string | null = null) {
    const jks = new Jks();
    jks.cert = cert;
    jks.key = key;
    if (password) {
      jks.password = password;
    }
    jks.prepareKey();

    return jks;
  }


  /**
   * 从JKS初始化实例
   *
   * @param jks JavaKeyStore Buffer
   * @param password 私钥密码，可不传
   * @returns {Jks}
   */
  static fromJKS(jksContent: ArrayBuffer, password: string) {
    const jks = new Jks();
    jks.jks = jksContent;
    jks.password = password;

    return jks;
  }

  /**
   * 从jks转换为pem
   *
   * @returns {PEM}
   */
  // public getPEM(): Promise<PEM> {
  //   return new Promise(async (resolve, reject) => {
  //     if (!this.cert || !this.key) {
  //       const keystore = jksJs.toPem(
  //         this.jks,
  //         this.password
  //       );
  //       for (const alias in keystore) {
  //         if (keystore.hasOwnProperty(alias)) {
  //           const data = keystore[alias];
  //           this.cert = data.cert;
  //           this.key = data.key;
  //         }
  //       }
  //     }
  //     const cert = this.cert;
  //     const key = this.key
  //     return resolve({cert, key});
  //   });
  // }

  prepareKey() {
    // detect is private key is rsa or ec by asn1.js
    const seq = ASN1.decode(Buffer.from(this.key.replace(/([\r\n]+|(-----(BEGIN|END) PRIVATE KEY-----)|(-----(BEGIN|END) (RSA|EC) PRIVATE KEY-----))/g, ''), 'base64'));
    if (seq.typeName() != 'SEQUENCE') {
      throw new Error('invalid key');
    }

    // secp384r1 06 05 2B 81 04 00 22
    // secp521r1 06 05 2B 81 04 00 23
    // secp256r1 06 05 2B 81 04 00 0A
    // secp256k1 06 05 2B 81 04 00 0B
    // secp224r1 06 05 2B 81 04 00 21
    // secp192r1 06 05 2B 81 04 00 0C
    // secp224k1 06 05 2B 81 04 00 20
    // secp192k1 06 05 2B 81 04 00 0D
    // ecPublicKey 06 07 2A 86 48 CE 3D 02 01
    // id-ecPublicKey 06 07 2A 86 48 CE 3D 02 01
    // rsaEncryption 06 09 2A 86 48 86 F7 0D 01 01 01
    const matches = {
      ['06 05 2B 81 04 00 22'.replace(/ /g, '')]: 'ec',
      ['06 05 2B 81 04 00 23'.replace(/ /g, '')]: 'ec',
      ['06 05 2B 81 04 00 0A'.replace(/ /g, '')]: 'ec',
      ['06 05 2B 81 04 00 0B'.replace(/ /g, '')]: 'ec',
      ['06 05 2B 81 04 00 21'.replace(/ /g, '')]: 'ec',
      ['06 05 2B 81 04 00 0C'.replace(/ /g, '')]: 'ec',
      ['06 05 2B 81 04 00 20'.replace(/ /g, '')]: 'ec',
      ['06 05 2B 81 04 00 0D'.replace(/ /g, '')]: 'ec',
      ['06 07 2A 86 48 CE 3D 02 01'.replace(/ /g, '')]: 'ec',
      ['06 07 2A 86 48 CE 3D 02 01'.replace(/ /g, '')]: 'ec',
      ['06 09 2A 86 48 86 F7 0D 01 01 01'.replace(/ /g, '')]: 'rsa',
    };

    const hex = seq.toHexString();

    for (const match in matches) {
      if (hex.indexOf(match) !== -1) {
        const buffer = Buffer.from(this.key.replace(/([\r\n]+|(-----(BEGIN|END) PRIVATE KEY-----)|(-----(BEGIN|END) (RSA|EC) PRIVATE KEY-----))/g, ''), 'base64');
        if (matches[match] === 'ec') {
          return this.prepareEcPrivateKey(buffer);
        } else {
          return this.prepareRsaPrivateKey(buffer);
        }
        return;
      }
    }
  }

  prepareRsaPrivateKey(privateKey: Buffer) {
    this.key = <string> rsaPKCS.toPKCS8(this.key);
  }

  prepareEcPrivateKey(privateKey: Buffer) {
    this.key = <string> ecPKCS.toPKCS8(this.key);
  }

  /**
   * @param {Buffer} plainKeyBuffer
   */
  async encryptPlainKey(plainKeyBuffer: Buffer, password: string) {
    let numRounds = 61; // the number of rounds

    const DIGEST_LEN = 20, SALT_LEN = 20;

    // Generate a random salt
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));

    // Initialize XOR key with zeros
    let xorKey = Buffer.alloc(plainKeyBuffer.length);
    // The password used for protecting/recovering keys passed through this
    // key protector.
    const passwdBytes = Buffer.alloc(password.length * 2);

    for (let i = 0, j = 0; i < password.length; i++) {
      passwdBytes[j++] = password[i].charCodeAt(0) >> 8;
      passwdBytes[j++] = password[i].charCodeAt(0);
    }
    // Compute the digests, and store them in "xorKey"
    for (let i = 0, xorOffset = 0, digest = salt; i < numRounds; i++, xorOffset += DIGEST_LEN) {
      digest = Buffer.from(await crypto.subtle.digest("SHA-1", Buffer.concat([passwdBytes, digest,])));

      // Copy the digest into "xorKey"
      if (i < numRounds - 1) {
        xorKey = Buffer.concat([
          xorKey.slice(0, xorOffset),
          digest,
        ]);
      } else {
        xorKey = Buffer.concat([
          xorKey.slice(0, xorOffset),
          digest.slice(0, plainKeyBuffer.length - xorOffset)
        ]);
      }
    }

    // XOR "plainKeyBuffer" with "xorKey", and store the result in "encrKey"
    const encrKey = Buffer.alloc(plainKeyBuffer.length);
    for (let i = 0; i < encrKey.length; i++) {
      encrKey[i] = plainKeyBuffer[i] ^ xorKey[i];
    }

    // Concatenate salt, encrKey, and digest for the final protected key
    let protectedKey = Buffer.concat([salt, encrKey]);

    // Compute the integrity digest and append it to the protected key
    const digest = Buffer.from(await crypto.subtle.digest("SHA-1", Buffer.concat([passwdBytes, plainKeyBuffer,])));
    protectedKey = Buffer.concat([protectedKey, digest,]);

    return protectedKey;
  }

  encryptPrivateKey(privateKey: Buffer, password: string): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      const encryptedData = await this.encryptPlainKey(privateKey, password);
      const algorithmIdentifier = 'pbeWithMD5AndDES-CBC';
      const KEY_PROTECTOR_OID = '1.3.6.1.4.1.42.2.17.1.1';

      const encrypt = asn1.define('encrypt', function (this: any) {
        this.seq().obj(
          this.key('encryptionAlgorithm').seq().obj(
            this.key('algorithm').objid({
              [KEY_PROTECTOR_OID]: 'pbeWithMD5AndDES-CBC',
            }),
            this.key('parameters').null_().optional(),
          ),
          this.key('encryptedData').octstr(),
        );
      });


      const output = encrypt.encode({
        encryptionAlgorithm: {
          algorithm: algorithmIdentifier,
          parameters: null,
        },
        encryptedData: encryptedData,
      }, 'der');

      return resolve(output);
    });
  }


  /**
   * 从pem转换为jks
   *
   * @param xVersion JKS版本号，1或2，默认2
   * @param password 私钥密码，不传时从实例获取密码
   * @returns {Promise<Buffer>}
   */
  public getJKS(xVersion: JKS_VERSION_1 | JKS_VERSION_2 = JKS_VERSION_2, password: string | null = null): Promise<ArrayBuffer> {
    return new Promise(async (resolve, reject) => {
      try {
        if (!this.cert) {
          return reject(new Error('cert is required'));
        }
        if (!this.key) {
          return reject(new Error('key is required'));
        }
        if (!password && !this.password) {
          return reject(new Error('password is required'));
        }

        if (!this.jks) {
          if (!password) {
            password = this.password;
          }

          this.stream.writeInt(JKS_MAGIC);

          // parse common name in cert PEM
          const cert = this.cert;
          // first PEM block
          const pemBlock = cert.split('-----END CERTIFICATE-----')[0];
          // PEM remove header and footer and new line
          const pem = pemBlock.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/-----END CERTIFICATE-----/, '').replace(/[\n\r]+/g, '');
          // base64 decode
          const pemBuffer = Buffer.from(pem, 'base64');

          // ans1js parse cert
          const asn1 = ans1js.fromBER(pemBuffer.buffer);
          const parse = new pkijs.Certificate({ schema: asn1.result });
          // get commonName
          const commonNameTypeValue = parse.subject.typesAndValues.find(
            (typeAndValue: any) => {
              return typeAndValue.type === '2.5.4.3'; // commonName OID
            }
          );

          let commonName = 'unknown';
          if (commonNameTypeValue && commonNameTypeValue.value && commonNameTypeValue.value.blockLength) {
            commonName = commonNameTypeValue.value.valueBlock.value;
          }
          // replace commonName dot and wildcard to underline
          const alias = commonName.replace(/\.|\*/g, '_');

          this.stream.writeInt(xVersion);

          // how many cert+keypairs
          const keyCount = 1;
          this.stream.writeInt(keyCount);

          // privateKey tag
          this.stream.writeInt(JKS_PRIVATE_KEY_TAG);

          // commonName
          const aliasLength = Buffer.byteLength(alias.substring(0, 255));
          this.stream.writeUTF(alias);

          // date, like '0x0000018c11d02835'
          // set to PEM's notBefore
          let notBefore = parse.notBefore?.value;
          if (!notBefore) {
            notBefore = new Date();
          }
          this.stream.writeLong(notBefore.getTime());

          // detect is private der
          const privateKeyBuffer = Buffer.from(this.key.replace(/(-----(BEGIN|END)( (RSA|EC))? PRIVATE KEY-----)|[\n\r]+/g, ''), 'base64');

          let encryptedPrivateKeyBuffer = await this.encryptPrivateKey(privateKeyBuffer, password);

          console.log('https://lapo.it/asn1js/#' + encryptedPrivateKeyBuffer.toString('base64').replace(/\+/, '-').replace(/\//, '_').replace(/=/, ''));

          this.stream.writeInt(encryptedPrivateKeyBuffer.byteLength);
          this.stream.write(encryptedPrivateKeyBuffer);

          const certBuffers = this.cert.split(/-----END( (RSA|EC))? CERTIFICATE-----/g).filter(item => item && item.trim()).map((item) => {
            const pem = item.replace(/(-----BEGIN( (RSA|EC))? CERTIFICATE-----)|[\n\r]+/g, '');
            const pemBuffer = Buffer.from(pem, 'base64');
            return pemBuffer;
          });

          this.stream.writeInt(certBuffers.length);

          for (const certBuffer of certBuffers) {
            // tag for certificate
            if (xVersion === JKS_VERSION_2) {
              // certType
              const certType = 'X.509';
              this.stream.writeUTF(certType);
            }

            // append cert
            this.stream.writeInt(certBuffer.byteLength);
            this.stream.write(certBuffer);
          }

          const passwordDigest = new PasswordDigest(this.stream.getBufferCopy(), password);
          const sum = await passwordDigest.digist();

          this.stream.write(Buffer.from(sum));
          this.jks = this.stream.getBuffer();
        }

        return resolve(this.jks);
      } catch (error) {
        return reject(error);
      }
    });
  }

  /**
   * 从pem转换pfx
   * @param password 私钥密码，不传时从实例获取密码
   */
  public getPfx(password: string) {
    // Convert PEM certificate to Forge certificate
    const certificate = forge.pki.certificateFromPem(this.cert);
    // Convert PEM private key to Forge private key
    const privateKey = forge.pki.privateKeyFromPem(this.key);
    // Create a PKCS#12 (PFX) object
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, [certificate], password);
    // Convert PKCS#12 (PFX) ASN.1 object to binary
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    return p12Der;
  }
}

(<any> window).Jks = Jks;
