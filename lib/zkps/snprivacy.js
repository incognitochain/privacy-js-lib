const bn = require('bn.js');
const { N } = require("../ec");
const { PedCom } = require("../pedersen");
const { generateChallenge } = require('./utils');
const { randScalar } = require('../privacy_utils');
const { SN_PRIVACY_PROOF_SIZE } = require('./constants');
const { COMPRESS_POINT_SIZE, BIG_INT_SIZE, SND, SK} = require('../constants');

class SNPrivacyProof {
    constructor() {
        this.serialNumber = null;
        this.comSK = null;
        this.comInput = null;
        this.tSK = null;
        this.tInput = null;
        this.tSN = null;
        this.zSK = null; //bn
        this.zRSK = null;
        this.zInput = null;
        this.zRInput = null;
    };

    set(serialNumber, comSK, comInput, tSK, tInput, tSN, zSK, zRSK, zInput, zRInput) {
        this.serialNumber = serialNumber; //EllipticPoint
        this.comSK = comSK;
        this.comInput = comInput;
        this.tSK = tSK;
        this.tInput = tInput;
        this.tSN = tSN;
        this.zSK = zSK; //bn
        this.zRSK = zRSK;
        this.zInput = zInput;
        this.zRInput = zRInput;
        return this
    }

    toBytes() {
        if (this.serialNumber == null) {
            return [];
        };
        let res = new Uint8Array(SN_PRIVACY_PROOF_SIZE);
        let offset = 0;

        res.set(this.serialNumber.compress(), offset);
        offset += COMPRESS_POINT_SIZE;
        res.set(this.comSK.compress(), offset);
        offset += COMPRESS_POINT_SIZE;
        res.set(this.comInput.compress(), offset);
        offset += COMPRESS_POINT_SIZE;
        res.set(this.tSK.compress(), offset);
        offset += COMPRESS_POINT_SIZE;
        res.set(this.tInput.compress(), offset);
        offset += COMPRESS_POINT_SIZE;
        res.set(this.tSN.compress(), offset);
        offset += COMPRESS_POINT_SIZE;
        res.set(this.zSK.toArray('be', BIG_INT_SIZE), offset);
        offset += BIG_INT_SIZE;
        res.set(this.zRSK.toArray('be', BIG_INT_SIZE), offset);
        offset += BIG_INT_SIZE;
        res.set(this.zInput.toArray('be', BIG_INT_SIZE), offset);
        offset += BIG_INT_SIZE;
        res.set(this.zRInput.toArray('be', BIG_INT_SIZE), offset);

        return res;
    }
    verify(mess = null) {
        let x = new bn();
        if (mess == null) {
            let bytesTmp = new Uint8Array(COMPRESS_POINT_SIZE * 3);
            bytesTmp.set(this.tSK.compress(), 0);
            bytesTmp.set(this.tInput.compress(), COMPRESS_POINT_SIZE);
            bytesTmp.set(this.tSN.compress(), COMPRESS_POINT_SIZE * 2);
            x = generateChallenge([bytesTmp]);
        } else {
            x = new bn(mess, 10, 'be');
        }
        if (!PedCom.commitAtIndex(this.zInput, this.zRInput, SND).eq(this.comInput.mul(x).add(this.tInput))) {
            return false;
        }
        if (!PedCom.commitAtIndex(this.zSK, this.zRSK, SK).eq(this.comSK.mul(x).add(this.tSK))) {
            return false;
        }
        return this.serialNumber.mul(this.zSK.clone().add(this.zInput)).eq(PedCom.G[SK].mul(x).add(this.tSN));
    }
}


class SNPrivacyWitness {
    constructor() {
        this.serialNumber = null;
        this.comSK = null;
        this.comInput = null;
        this.sk = null;
        this.rSK = null;
        this.input = null;
        this.rInput = null;
    }

    set(serialNumber, comSK, comInput, sk, rSK, input, rInput) {
        this.serialNumber = serialNumber;
        this.comSK = comSK;
        this.comInput = comInput;
        this.sk = sk;
        this.rSK = rSK;
        this.input = input;
        this.rInput = rInput;
    }

    prove(mess = null) {
        let eSK = randScalar();
        let eSND = randScalar();
        let dSK = randScalar();
        let dSND = randScalar();
        // calculate tSK = g_SK^eSK * h^dSK
        let tSK = PedCom.commitAtIndex(eSK, dSK, SK);

        // calculate tSND = g_SND^eSND * h^dSND
        let tInput = PedCom.commitAtIndex(eSND, dSND, SND);

        // calculate tSN = g_SK^eSND * h^dSND2
        let tSN = this.serialNumber.mul(eSK.toRed(N).redAdd(eSND.toRed(N)).fromRed());

        // calculate x = hash(tSK || tInput || tSN)
        let x = new bn();
        if (mess == null) {
            let bytesTmp = new Uint8Array(COMPRESS_POINT_SIZE * 3);
            bytesTmp.set(tSK.compress(), 0);
            bytesTmp.set(tInput.compress(), COMPRESS_POINT_SIZE);
            bytesTmp.set(tSN.compress(), COMPRESS_POINT_SIZE * 2);
            x = generateChallenge([bytesTmp]);
        } else {
            x = new bn(mess, 10, 'be');
        }

        // Calculate zSK = sk * x + eSK
        let zSK = this.sk.toRed(N).redMul(x.toRed(N)).redAdd(eSK.toRed(N)).fromRed();

        // Calculate zRSK = rSK * x + dSK
        let zRSK = this.rSK.toRed(N).redMul(x.toRed(N)).redAdd(dSK.toRed(N)).fromRed();

        // Calculate zInput = input * x + eSND
        let zInput = this.input.toRed(N).redMul(x.toRed(N)).redAdd(eSND.toRed(N)).fromRed();

        // Calculate zRInput = rInput * x + dSND
        let zRInput = this.rInput.toRed(N).redMul(x.toRed(N)).redAdd(dSND.toRed(N)).fromRed();

        return new SNPrivacyProof().set(this.serialNumber, this.comSK, this.comInput, tSK, tInput, tSN, zSK, zRSK, zInput, zRInput);
    }
}

module.exports = {
    SNPrivacyWitness,
    SNPrivacyProof
};