import DerValue from './DerValue';

class ObjectIdentifier {
    public encoding: Buffer;

    constructor(inputStream: any) {
        const typeId = inputStream.readByte();

        if (typeId !== DerValue.tag_ObjectId) {
            throw new Error('data isn\'t an object ID ( tag = ' + typeId + ')');
        }

        const length = DerValue.getLength(inputStream);

        this.encoding = inputStream.read(length);
    }

    public toString(): string {
        const length = this.encoding.length;
        let sb: string = '';
        let fromPos: number = 0;

        for (let i = 0; i < length; i++) {
            if ((this.encoding[i] & 0x80) === 0) {
                if (fromPos !== 0) {
                    sb += '.';
                }
                let retVal: number = 0;
                for (let j = fromPos; j <= i; j++) {
                    retVal <<= 7;
                    const tmp = this.encoding[j];
                    retVal |= (tmp & 0x07f);
                }
                if (fromPos === 0) {
                    if (retVal < 80) {
                        sb += Math.floor(retVal / 40);
                        sb += '.';
                        sb += retVal % 40;
                    } else {
                        sb += '2.';
                        sb += retVal - 80;
                    }
                } else {
                    sb += retVal;
                }
                fromPos = i + 1;
            }
        }
        return sb;
    }
}

export default ObjectIdentifier;
