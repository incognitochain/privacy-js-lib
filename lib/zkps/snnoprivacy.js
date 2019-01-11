let common = require("../common");
let ec = require("../ec");
let Pds = require("../pedersen").PedCom;
let cs = require("../constants");
let utils = require("../privacy_utils");

// type snNoPrivacyWitness struct {
// 	// general info
// 	serialNumber *privacy.EllipticPoint
// 	PK           *privacy.EllipticPoint
// 	SND          *big.Int

// 	sk *big.Int
// }

// // snNoPrivacyProof contains Proof's value
// type snNoPrivacyProof struct {
// 	// general info
// 	serialNumber *privacy.EllipticPoint
// 	PK           *privacy.EllipticPoint
// 	SND          *big.Int

// 	tSK *privacy.EllipticPoint
// 	tE  *privacy.EllipticPoint

// 	zSK *big.Int
// }

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
        return this.serialNumber.compress().concat(this.PK.compress()).concat(this.SND.toArray('be', cs.BigIntSize)).concat(tSK.compress()).concat(tE.compress()).concat(zSK.toArray('be',cs.BigIntSize));
    }
}


class SNNoPrivacyWitness {
    constructor(serialNumber,PK,SND,sk){
        this.serialNumber = serialNumber;
        this.PK = PK;
        this.SND = SND;
        this.sk = sk;
    }
    // fromBytes(bytes){
    //     this.serialNumber = ec.P256.decompress(bytes.slice(0, cs.CompressPointSize));
    //     this.PK = ec.P256.decompress(bytes.slice(cs.CompressPointSize, 2*cs.CompressPointSize));
    //     this.SND = new common.BigInt(bytes.slice(2*cs.CompressPointSize, 2*cs.CompressPointSize + cs.BigIntSize));
    //     this.sk = new common.BigInt(bytes.slice(2*cs.CompressPointSize + cs.BigIntSize, 2*cs.CompressPointSize + 2*cs.BigIntSize));
    // }
    prove(){
        if (this.PK === null){
            return null;
        }
        // let res = new Uint8Array(cs.CompressPointSize*4 + cs.BigIntSize*2);
        let eSK = utils.RandInt();
        let tSK = Pds.G[cs.SK].mul(eSK);
        let tE = this.serialNumber.mul(eSK);
        let x = utils.generateChallengeFromPoint((new Array(Pds.G)).push(tSK).push(tE));
        let zSK = this.sk.toRed(ec.moduleN).redMul(x.toRed(ec.moduleN)).redAdd(eSK.toRed(ec.moduleN)).fromRed();
        // res.set(this.serialNumber.compress(),0);
        // res.set(this.PK.compress(),cs.CompressPointSize);
        // res.set(this.SND.toArray('be', cs.BigIntSize),cs.CompressPointSize*2);
        // res.set(tSK.compress(),2*cs.CompressPointSize + cs.BigIntSize);
        // res.set(tE.compress(),3*cs.CompressPointSize + cs.BigIntSize);
        // res.set(zSK.toArray('be',cs.BigIntSize),4*cs.CompressPointSize + cs.BigIntSize);
        // return res;
        return new SNNoPrivacyProof(this.serialNumber, this.PK, this.SND, tSK,tE, zSK);
    }
}

module.exports = {SNNoPrivacyWitness, SNNoPrivacyProof};

