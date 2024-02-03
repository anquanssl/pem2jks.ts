import * as Asn1js from "asn1js";
import { Buffer } from "buffer/";

export default class rsaPKCS {
  static toPKCS1(key: string): string|null {
    try {
      const keyBase = <string> key.replace(/([\r\n]+|(-----(BEGIN|END) PRIVATE KEY-----)|(-----(BEGIN|END) (RSA|EC) PRIVATE KEY-----))/g, '');
      const pkcs = Asn1js.fromBER(Buffer.from(keyBase, 'base64').buffer);
      if ((<any> pkcs.result.valueBlock).value.length > 5) {
        return key;
      }

      let pkcs1Buffer = Buffer.from([0x02, 0x01, 0x00,]).buffer;

      for (let index = 1; index < (<any> pkcs.result.valueBlock).value[2].valueBlock.value[0].valueBlock.value.length; index ++) {
        pkcs1Buffer = Buffer.concat([Buffer.from(pkcs1Buffer), Buffer.from((<any> pkcs.result.valueBlock).value[2].valueBlock.value[0].valueBlock.value[index].valueBeforeDecode),]);
      }

      const length = pkcs1Buffer.byteLength;
      const lengthBuffer = new ArrayBuffer(2);
      const lengthView = new DataView(lengthBuffer);
      lengthView.setUint16(0, length, false);

      //write length to buffer with hex format
      pkcs1Buffer = Buffer.concat([Buffer.from([0x30, 0x82,]), Buffer.from(lengthView.buffer), Buffer.from(pkcs1Buffer), ]);

      let pkcs1 = `-----BEGIN RSA PRIVATE KEY-----\n`
      pkcs1 += Buffer.from(pkcs1Buffer).toString('base64').match(/.{1,64}/g)?.join('\n') + '\n';
      pkcs1 += `-----END RSA PRIVATE KEY-----`;

      return pkcs1;
    } catch (err) {
      console.error(err);
      return null;
    }
  }

  static toPKCS8(key: string): string|null {
    try {
      const buffer = Buffer.from(key.replace(/([\r\n]+|(-----(BEGIN|END)( (RSA|EC))? PRIVATE KEY-----))/g, ''), 'base64');
      const pkcs1Buffer = buffer.buffer;
      const pkcs = Asn1js.fromBER(pkcs1Buffer);

      if ((<any> pkcs.result.valueBlock).value.length < 5) {
        return key;
      }

      // Create a PKCS#8 ASN.1 structure
      const pkcs8Structure = new Asn1js.Sequence({
        value: [
          new Asn1js.Integer({ value: 0 }),
          new Asn1js.Sequence({
            value: [
              new Asn1js.ObjectIdentifier({
                value: "1.2.840.113549.1.1.1",
              }), // rsaEncryption
              new Asn1js.Null(),
            ],
          }),
          new Asn1js.OctetString({ valueHex: pkcs1Buffer }),
        ],
      });

      // Convert the PKCS#8 structure to BER format
      const pkcs8Buffer = pkcs8Structure.toBER(false);

      // Base64 encode the resulting buffer
      const pkcs8 = `-----BEGIN PRIVATE KEY-----\n` + Buffer.from(pkcs8Buffer).toString('base64').match(/.{1,64}/g)?.join('\n') + `-----END PRIVATE KEY-----`;

      return pkcs8;
    } catch (err) {
      console.error(err);
      return null;
    }
  }
};
