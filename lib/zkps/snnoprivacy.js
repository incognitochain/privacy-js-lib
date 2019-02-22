let BigInt = require('bn.js');
let ec = require("../ec");
let Pds = require("../pedersen").PedCom;
let cs = require("../constants");
let utils = require('./utils');
let privacy_utils = require('../privacy_utils');

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
            let res = new Uint8Array(cs.COMPRESS_POINT_SIZE * 4 + cs.BIG_INT_SIZE * 2);
            res.set(this.serialNumber.compress(), 0);
            res.set(this.PK.compress(), cs.COMPRESS_POINT_SIZE);
            res.set(this.SND.toArray('be', cs.BIG_INT_SIZE), cs.COMPRESS_POINT_SIZE * 2);
            res.set(tSK.compress(), 2 * cs.COMPRESS_POINT_SIZE + cs.BIG_INT_SIZE);
            res.set(tE.compress(), 3 * cs.COMPRESS_POINT_SIZE + cs.BIG_INT_SIZE);
            res.set(zSK.toArray('be', cs.BIG_INT_SIZE), 4 * cs.COMPRESS_POINT_SIZE + cs.BIG_INT_SIZE);
            return res;
        }
    }
    verify(mess = null) {
        let x = new BigInt;
        if (mess == null) {
            let bytesTmp = new Uint8Array(cs.COMPRESS_POINT_SIZE * 2);
            bytesTmp.set(this.tSK.compress(), 0);
            bytesTmp.set(this.tE.compress(), cs.COMPRESS_POINT_SIZE);
            x = utils.generateChallenge([bytesTmp]);
        } else {
            x = BigInt(mess, 10, 'be');
        }
        if (!Pds.G[cs.SK].mul(this.zSK).eq(this.PK.mul(x).add(this.tSK))) {
            return false;
        }
        return this.serialNumber.mul(this.zSK.clone().add(x.clone().mul(this.SND))).eq(Pds.G[cs.SK].mul(x).add(this.tE));
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

        let eSK = privacy_utils.randScalar();
        let tSK = Pds.G[cs.SK].mul(eSK);
        let tE = this.serialNumber.mul(eSK);
        let x = new BigInt;
        if (mess == null) {
            let bytesTmp = new Uint8Array(cs.COMPRESS_POINT_SIZE * 2);
            bytesTmp.set(tSK.compress(), 0);
            bytesTmp.set(tE.compress(), cs.COMPRESS_POINT_SIZE);
            x = utils.generateChallenge([bytesTmp]);
        } else {
            x = BigInt(mess, 10, 'be');
        }
        let zSK = this.sk.toRed(ec.N).redMul(x.toRed(ec.N)).redAdd(eSK.toRed(ec.N)).fromRed();
        return new SNNoPrivacyProof(this.serialNumber, this.PK, this.SND, tSK, tE, zSK);
    }
}

module.exports = {
    SNNoPrivacyWitness,
    SNNoPrivacyProof
};