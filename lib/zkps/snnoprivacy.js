var common = require("../common");
var ec = require("../ec");
var Pds = require("../pedersen").PedCom;
var cs = require("../constants");
var utils = require("../privacy_utils");

// type SNNoPrivacyWitness struct {
// 	// general info
// 	serialNumber *privacy.EllipticPoint
// 	PK           *privacy.EllipticPoint
// 	SND          *big.Int

// 	sk *big.Int
// }

// // SNNoPrivacyProof contains Proof's value
// type SNNoPrivacyProof struct {
// 	// general info
// 	serialNumber *privacy.EllipticPoint
// 	PK           *privacy.EllipticPoint
// 	SND          *big.Int

// 	tSK *privacy.EllipticPoint
// 	tE  *privacy.EllipticPoint

// 	zSK *big.Int
// }


class SNNoPrivacyWitness {
    constructor() {
        this.serialNumber = null;
        this.PK = null;
        this.SND = null;
        this.sk = null;
    }
    static fromValues(serialNumber,PK,SND,sk){
        var res = new SNNoPrivacyWitness();
        res.serialNumber = serialNumber;
        res.PK = PK;
        res.SND = SND;
        res.sk = sk;
        return res;
    }
    static fromBytes(bytes){
        var res = new SNNoPrivacyWitness();
        res.serialNumber = ec.P256.decompress(bytes.slice(0, cs.CompressPointSize));
        res.PK = ec.P256.decompress(bytes.slice(cs.CompressPointSize, 2*cs.CompressPointSize));
        res.SND = new common.BigInt(bytes.slice(2*cs.CompressPointSize, 2*cs.CompressPointSize + cs.BigIntSize));
        res.sk = new common.BigInt(bytes.slice(2*cs.CompressPointSize + cs.BigIntSize, 2*cs.CompressPointSize + 2*cs.BigIntSize));
        return res;
    }
    Prove(){
        if (this.PK === null){
            return null;
        }
        var res = new Uint8Array(cs.CompressPointSize*4 + cs.BigIntSize*2);
        var eSK = utils.RandInt();
        var tSK = Pds.G[cs.SK].mul(eSK);
        var tE = this.serialNumber.mul(eSK);
        var x = utils.generateChallengeFromPoint((new Array(Pds.G)).push(tSK).push(tE));
        var zSK = this.sk.toRed(ec.moduleN).redMul(x.toRed(ec.moduleN)).redAdd(eSK.toRed(ec.moduleN)).fromRed();
        res.set(this.serialNumber.compress(),0);
        res.set(this.PK.compress(),cs.CompressPointSize);
        res.set(this.SND.toArray('be', cs.BigIntSize),cs.CompressPointSize*2);
        res.set(tSK.compress(),2*cs.CompressPointSize + cs.BigIntSize);
        res.set(tE.compress(),3*cs.CompressPointSize + cs.BigIntSize);
        res.set(zSK.toArray('be',cs.BigIntSize),4*cs.CompressPointSize + cs.BigIntSize);
        return res;
    }
}