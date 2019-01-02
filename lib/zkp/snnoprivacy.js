var common = require("./../common");
var Pds = require("./../pedersen").PedCom;

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
        let res = new SNNoPrivacyWitness();
        res.serialNumber = serialNumber;
        res.PK = PK;
        res.SND = SND;
        res.sk = sk;
        return res;
    }
    static fromBytes(bytes){

    }
}