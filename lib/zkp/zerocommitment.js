var common = require("./../common");
var ec  = require("./../ec");
var utils = require("./../privacy_utils");
var PedCom = require("./../pedersen").PedCom;

// ComZeroProof contains Proof's value
// type ComZeroProof struct {
// 	commitmentValue *EllipticPoint //statement
// 	index           *byte                  //statement
// 	commitmentZeroS *EllipticPoint
// 	z               *big.Int
// }

// ComZeroWitness contains Witness's value
// type ComZeroWitness struct {
// 	commitmentValue *git EllipticPoint //statement
// 	index           *byte                  //statement
// 	commitmentRnd   *big.Int
// }

/*Protocol for opening a PedersenCommitment to 0 https://link.springer.com/chapter/10.1007/978-3-319-43005-8_1 (Fig. 5)
Prove:
	commitmentValue is PedersenCommitment value of Zero, that is statement needed to prove
	commitmentRnd is PRDNumber, which is used to calculate commitmentValue
	s <- Zp; P is privacy.Curve base point's order, is N
	B <- Comm_ck(0,s);  Comm_ck is PedersenCommit function using public params - privacy.Curve.Params() (G0,G1...)
						but is just commit special value (in this case, special value is 0),
						which is stick with G[Index] (in this case, Index is the Index stick with commitmentValue)
						B is a.k.a commitmentZeroS
	x <- Hash(G0||G1||G2||G3||commitmentvalue) x is pseudorandom number, which could be computed easily by Verifier
	z <- rx + s; z in Zp, r is commitmentRnd
	return commitmentZeroS, z
        this.
    };
*/

class ComZeroWitness {

    constructor(Bytes){
        this.commitmentValue = ec.P256.decompress(Bytes.slice(0,ec.CompressPointSize));
        this.index = Number(Bytes[ec.CompressPointSize]);
        this.Rnd = new common.BigInt(Bytes.slice(ec.CompressPointSize + 1, ec.CompressPointSize + 1 + ec.BigIntSize));
    };

    constructor(commitmentValue, index, Rnd){
        this.commitmentValue = commitmentValue;
        this.index = index;
        this.Rnd = Rnd;
    };

    Prove(){
        var res = new Uint8Array(2*ec.CompressPointSize + ec.BigIntSize + 1);
        res.set(this.commitmentValue.compress(), 0);
        res[ec.CompressPointSize]=this.index;
        var sRnd = utils.RandInt(ec.BigIntSize).toRed(ec.moduleN).fromRed();
        res.set(PedCom.CommitAtIndex(new common.BigInt(0), sRnd, this.index).compress(), ec.CompressPointSize + 1);
        res.set(sRnd.toArray('be',ec.BigIntSize),2*ec.CompressPointSize + 1);
        return res;
    };

};