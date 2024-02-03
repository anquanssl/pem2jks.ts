import * as Asn1js from "asn1js";
import { Buffer } from "buffer/";

export default class ecPKCS {
  static toPKCS8(key: string): string|null {
    // convert
    //    PrivateKeyInfo SEQUENCE (4 elem)
    //      version Version INTEGER 1
    //      privateKeyAlgorithm AlgorithmIdentifier [?] OCTET STRING (48 byte) 4FBC53278A4C839EB7A77548BDBC44D4A92959DF195513D011B14EB78D341D82805B56…
    //      privateKey PrivateKey [?] [0] (1 elem)
    //        OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
    //      [1] (1 elem)
    //        BIT STRING (776 bit) 0000010001111011001011010011001110011001100001001000100101111000110101…
    //
    //
    // to
    //
    //    PrivateKeyInfo SEQUENCE (3 elem)
    //      version Version INTEGER 0
    //      privateKeyAlgorithm AlgorithmIdentifier SEQUENCE (2 elem)
    //        algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
    //        parameters ANY OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
    //      privateKey PrivateKey OCTET STRING (158 byte) 30819B02010104304FBC53278A4C839EB7A77548BDBC44D4A92959DF195513D011B14…
    //        SEQUENCE (3 elem)
    //          INTEGER 1
    //          OCTET STRING (48 byte) 4FBC53278A4C839EB7A77548BDBC44D4A92959DF195513D011B14EB78D341D82805B56…
    //          [1] (1 elem)
    //            BIT STRING (776 bit) 0000010001111011001011010011001110011001100001001000100101111000110101…
    // format
    const ecOID = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,];
    const keyBase = <string> key.replace(/([\r\n]+|(-----(BEGIN|END)( (RSA|EC))? PRIVATE KEY-----))/g, '');
    console.log(keyBase);

    const privateKey = Buffer.from(keyBase, 'base64');
    // if privateKey contains Buffer.from(ecOID), return directly
    if (privateKey.indexOf(Buffer.from(ecOID)) !== -1) {
      return key;
    }

    const asn1js = Asn1js.fromBER(privateKey.buffer);
    console.log(asn1js);
    console.log('https://lapo.it/asn1js/#' + privateKey.toString('base64').replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, ''));

    const curveOID = (<any> asn1js.result.valueBlock).value[2].valueBlock.value[0];
    const privateKeyOctetString = (<any> asn1js.result.valueBlock).value[1];
    const privateKeyBitString = (<any> asn1js.result.valueBlock).value[3].valueBlock.value[0];

    console.log('curveOID', curveOID);
    console.log('privateKeyOctetString', privateKeyOctetString);
    console.log('privateKeyBitString', privateKeyBitString);

    let privateKeyBuffer = Buffer.alloc(0);
    privateKeyBuffer = Buffer.concat([Buffer.from(privateKeyBitString.valueBeforeDecode), privateKeyBuffer]);
    privateKeyBuffer = Buffer.concat([Buffer.from([privateKeyBitString.valueBeforeDecode.byteLength]), privateKeyBuffer]);
    privateKeyBuffer = Buffer.concat([Buffer.from([0xA1,]), privateKeyBuffer]);
    privateKeyBuffer = Buffer.concat([Buffer.from(privateKeyOctetString.valueBeforeDecode), privateKeyBuffer]);
    privateKeyBuffer = Buffer.concat([Buffer.from([0x02, 0x01, 0x01,]), privateKeyBuffer]);
    privateKeyBuffer = Buffer.concat([Buffer.from([privateKeyBuffer.byteLength]), privateKeyBuffer]);
    privateKeyBuffer = Buffer.concat([Buffer.from([0x30, 0x81,]), privateKeyBuffer]);
    privateKeyBuffer = Buffer.concat([Buffer.from([privateKeyBuffer.byteLength]), privateKeyBuffer]);
    privateKeyBuffer = Buffer.concat([Buffer.from([0x04, 0x81,]), privateKeyBuffer]);

    let privateKeyAlgorithm = Buffer.alloc(0);
    privateKeyAlgorithm = Buffer.concat([Buffer.from(curveOID.valueBeforeDecode), privateKeyAlgorithm]);
    privateKeyAlgorithm = Buffer.concat([Buffer.from(ecOID), privateKeyAlgorithm]);
    privateKeyAlgorithm = Buffer.concat([Buffer.from([privateKeyAlgorithm.byteLength]), privateKeyAlgorithm]);
    privateKeyAlgorithm = Buffer.concat([Buffer.from([0x30,]), privateKeyAlgorithm]);


    let versionBuffer = Buffer.from([0x02, 0x01, 0x00]);

    let keyBuffer = Buffer.concat([versionBuffer, privateKeyAlgorithm, privateKeyBuffer]);
    keyBuffer = Buffer.concat([Buffer.from([keyBuffer.byteLength]), keyBuffer]);
    keyBuffer = Buffer.concat([Buffer.from([0x30, 0x81,]), keyBuffer]);

    console.log('pkcs8 parsed', 'https://lapo.it/asn1js/#' + keyBuffer.toString('base64').replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, ''));

    return <string> `-----BEGIN PRIVATE KEY-----\n` + keyBuffer.toString('base64').match(/.{1,64}/g)?.join('\n') + `\n-----BEGIN PRIVATE KEY-----`;
  }
};
