let bn = require('bn.js');
const { N } = require("../ec");
const { PedCom } = require("../pedersen");
const { generateChallenge } = require('./utils');
const { randScalar } = require('../privacy_utils');
const { COMPRESS_POINT_SIZE, BIG_INT_SIZE, SK} = require('../constants');

class SNNoPrivacyProof {
    constructor(serialNumber, PK, SND, tSK, tE, zSK) {
        this.serialNumber = serialNumber;
        this.PK = PK;
        this.SND = SND;
        this.tSK = tSK;
        this.tE = tE;
        this.zSK = zSK;
    }
    toBytes() {
        if (this.serialNumber == null) {
            return [];
        } else {
            let res = new Uint8Array(COMPRESS_POINT_SIZE * 4 + BIG_INT_SIZE * 2);
            res.set(this.serialNumber.compress(), 0);
            res.set(this.PK.compress(), COMPRESS_POINT_SIZE);
            res.set(this.SND.toArray('be', BIG_INT_SIZE), COMPRESS_POINT_SIZE * 2);
            res.set(this.tSK.compress(), 2 * COMPRESS_POINT_SIZE + BIG_INT_SIZE);
            res.set(this.tE.compress(), 3 * COMPRESS_POINT_SIZE + BIG_INT_SIZE);
            res.set(this.zSK.toArray('be', BIG_INT_SIZE), 4 * COMPRESS_POINT_SIZE + BIG_INT_SIZE);
            return res;
        }
    }
    verify(mess = null) {
        let x = new bn();
        if (mess == null) {
            let bytesTmp = new Uint8Array(COMPRESS_POINT_SIZE * 2);
            bytesTmp.set(this.tSK.compress(), 0);
            bytesTmp.set(this.tE.compress(), COMPRESS_POINT_SIZE);
            x = generateChallenge([bytesTmp]);
        } else {
            x = bn(mess, 10, 'be');
        }
        if (!PedCom.G[SK].mul(this.zSK).eq(this.PK.mul(x).add(this.tSK))) {
            return false;
        }
        return this.serialNumber.mul(this.zSK.clone().add(x.clone().mul(this.SND))).eq(PedCom.G[SK].mul(x).add(this.tE));
    }
}


class SNNoPrivacyWitness {

    constructor() {
        this.serialNumber = null;
        this.PK = null;
        this.SND = null;
        this.sk = null;
    }

    set(serialNumber, PK, SND, sk) {
        this.serialNumber = serialNumber;
        this.PK = PK;
        this.SND = SND;
        this.sk = sk;
    }

    prove(mess = null) {
        if (this.PK === null) {
            return null;
        }

        let eSK = randScalar();
        let tSK = PedCom.G[SK].mul(eSK);
        let tE = this.serialNumber.mul(eSK);
        let x = new bn;
        if (mess == null) {
            let bytesTmp = new Uint8Array(COMPRESS_POINT_SIZE * 2);
            bytesTmp.set(tSK.compress(), 0);
            bytesTmp.set(tE.compress(), COMPRESS_POINT_SIZE);
            x = generateChallenge([bytesTmp]);
        } else {
            x = bn(mess, 10, 'be');
        }
        let zSK = this.sk.toRed(N).redMul(x.toRed(N)).redAdd(eSK.toRed(N)).fromRed();
        return new SNNoPrivacyProof(this.serialNumber, this.PK, this.SND, tSK, tE, zSK);
    }
}

module.exports = {
    SNNoPrivacyWitness,
    SNNoPrivacyProof
};