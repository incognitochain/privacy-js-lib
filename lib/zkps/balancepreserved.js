var common = require("../common");
var Curve = new common.Elliptic('p256');
var utils = require('../privacy_utils');
var bal_utils = require("./balancepreserved_utils");
var constant = require('../constants');
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
        this.maxExp = constant.MaxEXP;
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
        let rangeProofParams = new bal_utils.CryptoParams().InitCryptoParams(this.Values.length, this.maxExp);
        // console.log(rangeProofParams);
        let MRProof = new MultiRangeProof();
        MRProof.maxExp = this.maxExp;
        let m = this.Values.length;
        MRProof.Counter = m;
        let bitsPerValue = rangeProofParams.V/m;
        // we concatenate the binary representation of the values
        let PowerOfTwos = bal_utils.PowerVector(bitsPerValue, new common.BigInt("2"));
        let Comms = [];
        let gammas = [];
        let aLConcat = [];
        let aRConcat = [];
        // let sumRand = new common.BigInt("0");
        for (let j=0;j<this.Values.length;j++){
            let v = this.Values[j];
            if(v.cmp(new common.BigInt("0"))=== -1){
                return null
            }
            if (v.cmp(new common.BigInt(constant.MaxValue.toString(10),10))===1){
                return null
            }
            // let gamma = utils.RandInt(32);
            let gamma = new common.BigInt("123456789").mul(new common.BigInt(j+1));
            Comms[j] = rangeProofParams.G.mul(v).add(rangeProofParams.H.mul(gamma));
            gammas[j] = gamma;
            this.Rands[j] = gamma;
            // break up v into its bitwise representation
            let aL = bal_utils.reverse(bal_utils.StrToBigIntArray(bal_utils.PadLeft(v.toString(2,null),"0",bitsPerValue)));
            let aR = bal_utils.VectorAddScalar(aL,new common.BigInt(-1));
            for (let i =0;i<aR.length;i++){
                aLConcat[bitsPerValue*j+i] = aL[i];
                aRConcat[bitsPerValue*j+i] = aR[i];
            }
        }
        MRProof.Comms = Comms;
        this.Comms = Comms;
        // console.log(Comms);
        let alpha  = utils.RandInt(32);
        let A = bal_utils.TwoVectorPCommitWithGens(rangeProofParams.BPG, rangeProofParams.BPH, aLConcat, aRConcat);
        A = A.add(rangeProofParams.H.mul(alpha));
        if (A===null){
            return null;
        }
        else{
            MRProof.A = A;
        }
        let sL = bal_utils.RandVector(rangeProofParams.V);
        let sR = bal_utils.RandVector(rangeProofParams.V);
        let rho = utils.RandInt(32);
        let S = bal_utils.TwoVectorPCommitWithGens(rangeProofParams.BPG, rangeProofParams.BPH,aLConcat, aRConcat);
        S = S.add(rangeProofParams.H.mul(alpha));
        if (S===null){
            return null;
        }
        else{
            MRProof.S = S;
        }
        console.log(A);
        let hashdata1 = A.getX().toString(10,null) + A.getY().toString(10,null);
        let chal1s256 = common.HashBytesToBytes(utils.stringToBytes(hashdata1));
        MRProof.Cy = utils.ByteArrToInt(chal1s256);

        let hashdata2 = S.getX().toString(10,null) + S.getX().toString(10,null);
        let chal2s256 = common.HashBytesToBytes(utils.stringToBytes(hashdata2));
        MRProof.Cz = utils.ByteArrToInt(chal2s256);

        let zPowersTimesTwoVec = [];
        for (let j = 0; j < m; j++) {
            let challengeZ = MRProof.Cz;
            let zp = challengeZ.pow(new common.BigInt((2+j).toString(10),10));
            zp = zp.umod(Curve.n);
            for (let i = 0; i < bitsPerValue; i++) {
                let tmp = PowerOfTwos[i];
                zPowersTimesTwoVec[j*bitsPerValue+i] = tmp.mul(zp).umod(Curve.n);
            }
        }
        let PowerOfCy = bal_utils.PowerVector(rangeProofParams.V, MRProof.Cy);
        let l0 = bal_utils.VectorAddScalar(aLConcat, MRProof.Cz.neg());
        let l1 = sL;
        let r0 = bal_utils.VectorAdd(bal_utils.VectorHadamard(PowerOfCy,bal_utils.VectorAddScalar(aRConcat, MRProof.Cz)),zPowersTimesTwoVec);
        let r1 = bal_utils.VectorHadamard(sR,PowerOfCy);
        //calculate t0
        let vz2 = new common.BigInt("0");
        let cz = MRProof.Cz;
        let z2 = cz.mul(cz).umod(Curve.n);
        let PowerOfCz = bal_utils.PowerVector(m, MRProof.Cz);
        for (let j=0;j<m;j++){
            vz2 = vz2.add(PowerOfCz[j].mul(this.Values[j].mul(z2)));
            vz2 = vz2.umod(Curve.n);
        }
        let t0 = vz2.add(bal_utils.DeltaMRP(PowerOfCy,MRProof.Cz,m,rangeProofParams));
        t0 = t0.umod(Curve.n);
        let t1 = bal_utils.InnerProduct(l1,r0);
        t1 = t1.add(bal_utils.InnerProduct(l0,r1));
        t1 = t1.umod(Curve.n);
        let t2 = bal_utils.InnerProduct(l1,r1);
        if (t2==null){
            return null;
        }
        // given the t_i values, we can generate commitments to them
        let tau1 = utils.RandInt(32);
        let tau2 = utils.RandInt(32);
        let T1 = rangeProofParams.G.mul(t1).add(rangeProofParams.H.mul(tau1));
        let T2 = rangeProofParams.G.mul(t2).add(rangeProofParams.H.mul(tau2));
        MRProof.T1 = T1;
        MRProof.T2 = T2;

        let hashdata3 = T1.getX().toString(10,null) + T1.getX().toString(10,null)+ T2.getX().toString(10,null) + T2.getX().toString(10,null);
        let chal3p256 = common.HashBytesToBytes(utils.stringToBytes(hashdata3));
        MRProof.Cx = utils.ByteArrToInt(chal2s256);

        let left = bal_utils.CalculateLMRP(aLConcat,sL,MRProof.Cz, MRProof.Cx);
        let right = bal_utils.CalculateRMRP(aRConcat,sR,PowerOfCy,zPowersTimesTwoVec, MRProof.Cz, MRProof.Cx);

        // t0 + t1*x + t2*x^2
        let t1MulX = t1.mul(MRProof.Cx);
        let t2MulSqrX = t2.mul(MRProof.Cx).mul(MRProof.Cx);
        let thatPrime = t0.add(t1MulX).add(t2MulSqrX);
        thatPrime = thatPrime.umod(Curve.n);
        let that = bal_utils.InnerProduct(left,right);
        that = that.umod(Curve.n);
        // console.log(that.toString(10,null), thatPrime.toString(10,null), Curve.n.toString(10,null));
        if (that.cmp(thatPrime)!==0){
            return null
        }
        return MRProof
    }

}
function Test() {
    let l = 5;
    let V = [];

    // for (let i=0;i<l;i++){
    //     V[i] = utils.RandInt(8)
    //    // console.log(V[i].toString(10, ""))
    // }
    V[0] = new common.BigInt("6755345518420511111",10);
    V[1] = new common.BigInt("3694924673900965606",10);

    a = new MultiRangeWitness();
    a.set(V,64);
    // console.log(a);
    proof = a.Prove();
    console.log(proof)
}
// console.log(new MultiRangeProof());
// console.log(new MultiRangeWitness());
Test();
// x = new bal_utils.CryptoParams().InitCryptoParams(4,64).BPH
// y = new bal_utils.CryptoParams().InitCryptoParams(4,64).H;
// console.log(x.getX().toString(10,null),x.getY().toString(10,null));
// for (let i=0;i<x.length;i++){
//     console.log("&{"+x[i].getX().toString(10,null),x[i].getY().toString(10,null)+"}");
// }

x = Curve.curve.point(new common.BigInt("220972225210613587092803207004116645329725881335810831594666496175168808161"),new common.BigInt("47109726179636173975559935971973816499842974684167213985561799433310741900221"));
console.log(x.getX().toString(10,null),x.getY().toString(10,null));
y = x.hash(0);
console.log(x.hash(0).getX().toString(10,null),x.hash(0).getY().toString(10,null));

z = Curve.curve.point(new common.BigInt("36151787796040926116474505734917038331733277882630097517119716008390589266476"),new common.BigInt("97225466038482204218083683873444136647031569327106994981785194666182351853594"));
console.log(y.add(z));


// var pedCom = require('../pedersen');
// var constant = require('../constants');
// console.log(pedCom.PedCom.G[constant.SND].getX().toString(10,null),pedCom.PedCom.G[constant.SND].getY().toString(10,null));