let common = require("../common");
let ec = require("../ec");
let Pds = require("../pedersen").PedCom;
let cs = require("../constants");
let utils = require('./utils');
let privacy_utils = require('../privacy_utils');

class SNNoPrivacyProof {
    constructor(serialNumber, PK, SND, tSK, tE, zSK){
        this.serialNumber = serialNumber;
        this.PK = PK;
        this.SND = SND;
        this.tSK = tSK;
        this.tE = tE;
        this.zSK =zSK;
    }
    toBytes(){
        if (this.serialNumber==null){
            return [];
        } else {
            let res = new Uint8Array(cs.CompressPointSize*4+cs.BigIntSize*2);
            res.set(this.serialNumber.compress(),0);
            res.set(this.PK.compress(),cs.CompressPointSize);
            res.set(this.SND.toArray('be', cs.BigIntSize),cs.CompressPointSize*2);
            res.set(tSK.compress(),2*cs.CompressPointSize + cs.BigIntSize);
            res.set(tE.compress(),3*cs.CompressPointSize + cs.BigIntSize);
            res.set(zSK.toArray('be',cs.BigIntSize),4*cs.CompressPointSize + cs.BigIntSize);
            return res;
        }
    }
}


class SNNoPrivacyWitness {

    constructor(){
        this.serialNumber = null;
        this.PK = null;
        this.SND = null;
        this.sk = null;
    }

    set(serialNumber,PK,SND,sk){
        this.serialNumber = serialNumber;
        this.PK = PK;
        this.SND = SND;
        this.sk = sk;
    }

    prove(mess=null){
        if (this.PK === null){
            return null;
        }

        let eSK = privacy_utils.RandScalar();
        let tSK = Pds.G[cs.SK].mul(eSK);
        let tE = this.serialNumber.mul(eSK);
        let x = new common.BigInt;
        if (mess==null){
            let bytesTmp = new Uint8Array(cs.CompressPointSize*2);
            bytesTmp.set(tSK.compress(),0);
            bytesTmp.set(tE.compress(),cs.CompressPointSize);
            x = utils.generateChallenge(bytesTmp);
        } else {
            x = common.BigInt(mess,10,'be');
        }
        let zSK = this.sk.toRed(ec.moduleN).redMul(x.toRed(ec.moduleN)).redAdd(eSK.toRed(ec.moduleN)).fromRed();
        return new SNNoPrivacyProof(this.serialNumber, this.PK, this.SND, tSK,tE, zSK);
    }
}

module.exports = {SNNoPrivacyWitness, SNNoPrivacyProof};

