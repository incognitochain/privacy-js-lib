var common = require("../common");
var Curve = new common.Elliptic('p256');
var utils = require('../privacy_utils')
var bal_utils = require("../zkps/balancepreserved_utils")

class MultiRangeProof{
    constructor(){
        this.Counter = 0;
        this.Comms = null;
        this.A =  bal_utils.ZeroPoint();
        this.S =  bal_utils.ZeroPoint();
        this.T1 = bal_utils.ZeroPoint();
        this.T2 = bal_utils.ZeroPoint;
        this.Tau = new common.BigInt("0");
        this.Th = new common.BigInt("0");
        this.Mu = new common.BigInt("0");
        this.IPP = new bal_utils.InnerProdArg();
        this.maxExp = 0;
        this.Cx = new common.BigInt("0");
        this.Cy = new common.BigInt("0");
        this.Cz = new common.BigInt("0");
    };
}
class MultiRangeWitness{
    constructor(){
        this.Comms = [];
        this.Values = [];
        this.Rands = [];
        this.maxExp = 64;
    }
    set(v,maxExp){
        let l = bal_utils.Pad(v.length +1);
        for (let i=0;i<l;i++){
            this.Values[i] = new common.BigInt("0");
        }
        var total = new common.BigInt("0");
        for (let i=0;i<v.length;i++){
            this.Values[i] = v[i];
            total.add(v[i]);
        }
        this.Values[l-1] = total;
        this.maxExp = maxExp
    }
    Prove(){
        // RangeProofParams.V has the total number of values and bits we can support
        let rangeProofParams = bal_utils.InitCryptoParams(this.Values.length, this.maxExp);
        console.log(rangeProofParams);
        let MRProof = new MultiRangeProof();
        MRProof.maxExp = this.maxExp;
        let m = this.Values.length;
        MRProof.Counter = m;
        let bitsPerValue = rangeProofParams.V/m;
        // we concatenate the binary representation of the values

    }

}
// function Test() {
//     let l = 5;
//     let V = [];
//
//     for (let i=0;i<l;i++){
//         V[i] = utils.RandInt(32)
//        // console.log(V[i].toString(10, ""))
//     }
//     a = new MultiRangeWitness()
//     a.set(V,64)
//     console.log(a);
// }
// console.log(new MultiRangeProof());
// console.log(new MultiRangeWitness());
// Test();