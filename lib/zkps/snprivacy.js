let common = require("../common");
let ec = require("../ec");
let Pds = require("../pedersen").PedCom;
let cs = require("../constants");
let utils = require("../privacy_utils");

class SNPrivacyProof {
    constructor(){
        this.serialNumber = null;//EllipticPoint
        this.comSK = null;       //--
        this.comInput = null;    //--
        this.tSK = null;         //--
        this.tInput = null;      //--
        this.tSN = null;         //--
        this.zSK = null;         //BigInt
        this.zRSK = null;        //--
        this.zInput = null;      //--
        this.zRInput = null;     //--
    };

    fromValue(serialNumber, comSK, comInput, tSK, tInput, tSN, zSK, zRSK, zInput, zRInput) {
        this.serialNumber = serialNumber;//EllipticPoint
        this.comSK = comSK;              //--
        this.comInput = comInput;        //--
        this.tSK = tSK;                  //--
        this.tInput = tInput;            //--
        this.tSN = tSN;                  //--
        this.zSK = zSK;                  //BigInt
        this.zRSK = zRSK;                //--
        this.zInput = zInput;            //--
        this.zRInput = zRInput;          //--
    }

    toBytes(){
        if (this.serialNumber == null){
            return [];
        };
        let res = new Uint8Array(cs.SNPrivacyProofSize);
        let offset = 0;
        res.set(this.serialNumber.compress(),offset);
        offset+=cs.CompressPointSize;
        res.set(this.comSK.compress(), offset);
        offset+=cs.ComZeroProofSize;
        res.set(this.comInput.compress(), offset);
        offset+=cs.ComZeroProofSize;
        res.set(this.tSK.compress(), offset);
        offset+=cs.ComZeroProofSize;
        res.set(this.tInput.compress(), offset);
        offset+=cs.ComZeroProofSize;
        res.set(this.tSN.compress(), offset);
        offset+=cs.ComZeroProofSize;
        res.set(this.zSK.toArray('be',cs.BigIntSize), offset);
        offset+=cs.BigIntSize;
        res.set(this.zRSK.toArray('be',cs.BigIntSize), offset);
        offset+=cs.BigIntSize;
        res.set(this.zInput.toArray('be',cs.BigIntSize), offset);
        offset+=cs.BigIntSize;
        res.set(this.zRInput.toArray('be',cs.BigIntSize), offset);
        offset+=cs.BigIntSize;
        return res;
    }
}


class SNPrivacyWitness {
    constructor(){
        this.serialNumber = null;
        this.comSK = null;
        this.comInput = null;
        this.sk = null;
        this.rSK = null;
        this.input = null;
        this.rInput = null;
    }

    set(serialNumber, comSK, comInput, sk, rSK, input, rInput){
        this.serialNumber = serialNumber;
        this.comSK = comSK;
        this.comInput = comInput;
        this.sk = sk;
        this.rSK = rSK;
        this.input = input;
        this.rInput = rInput;
    }

    fromByte4Test(serialNumber, comSK, comInput, sk, rSK, input, rInput){
        this.serialNumber = ec.P256.decompress(serialNumber);
        this.comSK = ec.P256.decompress(comSK);
        this.comInput = ec.P256.decompress(comInput);
        this.sk = new common.BigInt(sk,'be');
        this.rSK = new common.BigInt(rSK,'be');
        this.input = new common.BigInt(input, 'be');
        this.rInput = new common.BigInt(rInput, 'be');
    }

    prove(mess){
        let eSK = utils.RandInt();
	    let eSND = utils.RandInt();
	    let dSK = utils.RandInt();
        let dSND = utils.RandInt();
        // calculate tSK = g_SK^eSK * h^dSK
	    let tSK = Pds.CommitAtIndex(eSK, dSK, cs.SK);

	    // calculate tSND = g_SND^eSND * h^dSND
	    let tInput = Pds.CommitAtIndex(eSND, dSND, cs.SND);

	    // calculate tSN = g_SK^eSND * h^dSND2
	    let tSN = this.serialNumber.mul(eSK.toRed(ec.moduleN).redAdd(eSND).fromRed());

	    // calculate x = hash(tSK || tInput || tSN)
	    let x = new common.BigInt;
	    if (mess == null) {
    		x = utils.generateChallengeFromPoint(tSK, tInput, tSN);
    	} else {
		    x = common.BigInt(mess,10,'be');
	    }

	    // Calculate zSK = sk * x + eSK
	    let zSK = this.sk.toRed(ec.moduleN).redMul(x).redAdd(eSK).fromRed();

    	// Calculate zRSK = rSK * x + dSK
        let zRSK = this.rSK.toRed(ec.moduleN).redMul(x).redAdd(dSK).fromRed();

    	// Calculate zInput = input * x + eSND
	    let zInput = this.input.toRed(ec.moduleN).redMul(x).redAdd(eSND).fromRed();

	    // Calculate zRInput = rInput * x + dSND
        let zRInput = this.rInput.toRed(ec.moduleN).redMul(x).redAdd(dSND).fromRed();

        return new SNPrivacyProof(this.serialNumber, this.comSK, this.comInput, tSK, tInput, tSN, zSK, zRSK, zInput, zRInput);
    }
}

// let a = new SNPrivacyWitness;
// a.fromByte4Test([3,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
// console.log(a.serialNumber.getX().toString(), a.serialNumber.getY().toString());

module.exports = {SNPrivacyWitness, SNPrivacyProof};

