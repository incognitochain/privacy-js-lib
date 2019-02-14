var common = require("../common");
var Curve = new common.Elliptic('p256');
var utils = require('../privacy_utils');
var bal_utils = require("./aggregatedrange_utils");
var constants = require('../constants');
var params = require("./aggregaterangeparams");
var PedCom = require("../pedersen").PedCom;


class AggregatedRangeProof{
    constructor() {
        this.cmsValue = [];
        this.A = bal_utils.ZeroPoint;
        this.S = bal_utils.ZeroPoint;
        this.T1 = bal_utils.ZeroPoint;
        this.T2 = bal_utils.ZeroPoint;
        this.tauX = new common.BigInt("0");
        this.tHat = new common.BigInt("0");
        this.mu = new common.BigInt("0");
        this.innerProductProof = new bal_utils.InnerProductProof()
    }
}
class AggregatedRangeWitness {
    constructor(values, rands) {
        let numValue = values.length;
        this.values = [];
        this.rands = [];
        for (let i = 0; i < numValue; i++) {
            this.values[i] = values[i];
            this.rands[i] = rands[i];
        }
    }
    Prove() {
        let proof = new AggregatedRangeProof();
        let numValue = this.values.length;
        let numValuePad = bal_utils.Pad(numValue);
        let values = [];
        let rands = [];
        for (let i = 0; i < numValuePad; i++) {
            values[i] = this.values[i];
            rands[i] = this.rands[i];
        }
        for (let i = numValue; i < numValuePad; i++) {
            values[i] = new common.BigInt("0");
            rands[i] = new common.BigInt("0");
        }
        let AggParam = new params.BulletproofParams(numValuePad);
        proof.cmsValue = [];
        for (let i = 0; i < numValue; i++) {
            proof.cmsValue[i] = PedCom.CommitAtIndex(values[i], rands[i], constants.VALUE)
        }
        for (let i = numValue; i < numValuePad; i++) {
            proof.cmsValue[i] = bal_utils.ZeroPoint
        }
        let n = constants.MaxEXP;
        let aL = [];
        for (let i = 0; i < values.length; i++) {
            let tmp = utils.ConvertIntToBinary(values[i], n);
            for (let j = 0; j < n; j++) {
                aL[i * n + j] = new common.BigInt(tmp[j])
            }
        }
        let numberTwo = new common.BigInt("2");
        let vectorMinusOne = [];
        for (let i = 0; i < n * numValuePad; i++) {
            vectorMinusOne[i] = new common.BigInt("-1")
        }
        let vector2powN = bal_utils.PowerVector(numberTwo, n);
        let aR = bal_utils.VectorAdd(aL, vectorMinusOne);
        let alpha = utils.RandScalar();
        let A = params.EncodeVectors(aL, aR, AggParam.G, AggParam.H);
        A = A.add(PedCom.G[constants.RAND].mul(alpha));
        proof.A = A;
        // Random blinding vectors sL, sR
        let sL = [];
        let sR = [];
        for (let i = 0; i < n*numValuePad; i++) {
            sL[i] = utils.RandScalar();
            sR[i] = utils.RandScalar();
        }
        let rho = utils.RandScalar();
        let S = params.EncodeVectors(sL, sR, AggParam.G, AggParam.H);
        S = S.add(PedCom.G[constants.RAND].mul(rho));
        proof.S = S;

        // challenge y, z

        let y = params.generateChallengeForAggRange(AggParam, [A.compress(), S.compress()]);
        let z = params.generateChallengeForAggRange(AggParam, [A.compress(), S.compress(), y.toArray("be")])
        let zNeg = z.neg();
        zNeg = zNeg.umod(zNeg,Curve.n);
        let zSquare = z.mul(z);
        zSquare = zSquare.umod(Curve.n);

        let vectorPowOfY = bal_utils.PowerVector(y,n*numValuePad);
        let l0 = bal_utils.VectorAddScalar(aL, zNeg);
        let l1 = sL;
        // r(X) = y^n hada (aR +z*1^n + sR*X) + z^2 * 2^n
        let hadaProduct = bal_utils.HadamardProduct(vectorPowOfY, bal_utils.VectorAddScalar(aR, z));

        let vectorSum = [];
        let zTmp = z;
        for (let j=0;j<numValuePad;j++){
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(Curve.n);
            for (let i=0;i<n;i++){
                vectorSum[j*n+i] = vector2powN[i].mul(zTmp);
                vectorSum[j*n+i] = vectorSum[j*n+i].umod(Curve.n);
            }
        }
        let r0 = bal_utils.VectorAdd(hadaProduct, vectorSum);
        let r1 = bal_utils.HadamardProduct(vectorPowOfY,sR);
        //t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2
        let deltaYZ = z.sub(zSquare);
        let innerProduct1 = new common.BigInt("0");

        // innerProduct1 = <1^(n*m), y^(n*m)>
        for (let i=0;i<vectorPowOfY.length;i++){
            innerProduct1 = innerProduct1.add(vectorPowOfY[i])
        }
        deltaYZ = deltaYZ.mul(innerProduct1);

        // innerProduct2 = <1^n, 2^n>
        let innerProduct2 = new common.BigInt("0");
        for (let i=0;i<vector2powN.length;i++){
            innerProduct1 = innerProduct1.add(vector2powN[i])
        }

        let sum = new common.BigInt("0");
        zTmp = zSquare;
        for (let j=0;j<numValuePad;j++){
            zTmp = zTmp.mul(z);
            zTmp.umod(Curve.n);
            sum = sum.add(zTmp);
        }
        sum = sum.mul(innerProduct2);
        deltaYZ = deltaYZ.sub(sum);
        deltaYZ = deltaYZ.umod(Curve.n);
        // t1 = <l1, r0> + <l0, r1>
        let innerProduct3 = bal_utils.InnerProduct(l1, r0);
        let innerProduct4 = bal_utils.InnerProduct(l0, r1);

        let t1 = innerProduct3.add(innerProduct4);
        t1 = t1.umod(Curve.n);

        let t2 = bal_utils.InnerProduct(l1,r1);

        // commitment to t1, t2
        let tau1 = utils.RandScalar();
        let tau2 = utils.RandScalar();

        proof.T1 = PedCom.CommitAtIndex(t1,tau1,constants.VALUE);
        proof.T2 = PedCom.CommitAtIndex(t2, tau2,constants.VALUE);

        // challenge x = hash(G || H || A || S || T1 || T2)
        let x = params.generateChallengeForAggRange(AggParam,[proof.A.compress(), proof.S.compress(), proof.T1.compress(), proof.T2.compress()])
        let xSquare = x.pow(numberTwo);
        xSquare = xSquare.umod(Curve.n);

        // lVector = aL - z*1^n + sL*x
        let lVector = bal_utils.VectorAdd(bal_utils.VectorAddScalar(aL, zNeg), bal_utils.VectorMulScalar(sL, x));
        // rVector = y^n hada (aR +z*1^n + sR*x) + z^2*2^n
        let tmpVector= bal_utils.VectorAdd(bal_utils.VectorAddScalar(aR, z), bal_utils.VectorMulScalar(sR, x));
        let rVector = bal_utils.HadamardProduct(vectorPowOfY, tmpVector);


        vectorSum = [];
        zTmp = z;
        for (let j=0;j<numValuePad;j++){
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(Curve.n);
            for (let i=0;i<n;i++){
                vectorSum[j*n+i] = vector2powN[i].mul(zTmp);
                vectorSum[j*n+i] = vectorSum[j*n+i].umod(Curve.n);
            }
        }
        rVector = bal_utils.VectorAdd(rVector,vectorSum);
        // tHat = <lVector, rVector>
        proof.tHat = bal_utils.InnerProduct(lVector, rVector);
        // blinding value for tHat: tauX = tau2*x^2 + tau1*x + z^2*rand
        proof.tauX = tau2.mul(xSquare);
        proof.tauX = proof.tauX.add(tau1.mul(x));
        zTmp = z;
        for (let j=0;j<numValuePad;j++){
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(Curve.n);
            proof.tauX = proof.tauX.add(zTmp.mul(rands[j]))
        }
        proof.tauX = proof.tauX.umod(Curve.n);
        // alpha, rho blind A, S
        // mu = alpha + rho*x
        proof.mu = rho.mul(x);
        proof.mu = proof.mu.add(alpha);
        proof.mu = proof.mu.umod(Curve.n);

        // instead of sending left vector and right vector, we use inner sum argument to reduce proof size from 2*n to 2(log2(n)) + 2
        let innerProductWit = new bal_utils.InnerProductWitness();
        innerProductWit.a  = lVector;
        innerProductWit.b  = rVector;
        innerProductWit.p  = params.EncodeVectors(lVector,rVector,AggParam.G, AggParam.H);
        innerProductWit.p  = innerProductWit.p.add(AggParam.U.mul(proof.tHat));
        proof.innerProductProof = innerProductWit.Prove(AggParam);
        return proof
    }
}

let numValue = 1;
let values = [];
let rands  = [];
for (let i=0;i<numValue;i++){
    values[i] = new common.BigInt("10");
    rands[i] = utils.RandScalar(8);
}
let wit = new AggregatedRangeWitness(values,rands);
let proof = wit.Prove();
console.log(proof);




































// class AggregatedRangeProof{
//     constructor(){
//         this.Counter = 0;
//         this.Comms = null;
//         this.A =  bal_utils.ZeroPoint;
//         this.S =  bal_utils.ZeroPoint;
//         this.T1 = bal_utils.ZeroPoint;
//         this.T2 = bal_utils.ZeroPoint;
//         this.Tau = new common.BigInt("0");
//         this.Th = new common.BigInt("0");
//         this.Mu = new common.BigInt("0");
//         this.IPP = new bal_utils.InnerProdArg();
//         this.maxExp = 0;
//         this.Cx = new common.BigInt("0");
//         this.Cy = new common.BigInt("0");
//         this.Cz = new common.BigInt("0");
//     };
//
//     toBytes(){
//         return [];
//     }
// }
// class AggregatedRangeWitness{
//     constructor(){
//         this.Comms = [];
//         this.Values = [];
//         this.Rands = [];
//         this.maxExp = constants.MaxEXP;
//     }
//     set(v,maxExp){
//         let l = bal_utils.Pad(v.length +1);
//         for (let i=0;i<l;i++){
//             this.Values[i] = new common.BigInt("0");
//         }
//         var total = new common.BigInt("0");
//         for (let i=0;i<v.length;i++){
//             this.Values[i] = v[i];
//             total.add(v[i]);
//         }
//         this.Values[l-1] = total;
//         this.maxExp = maxExp
//     }
//     prove(){
//         // RangeProofParams.V has the total number of values and bits we can support
//         let rangeProofParams = new bal_utils.CryptoParams().InitCryptoParams(this.Values.length, this.maxExp);
//         // console.log(rangeProofParams);
//         let MRProof = new AggregatedRangeProof();
//         MRProof.maxExp = this.maxExp;
//         let m = this.Values.length;
//         MRProof.Counter = m;
//         let bitsPerValue = rangeProofParams.V/m;
//         // we concatenate the binary representation of the values
//         let PowerOfTwos = bal_utils.PowerVector(bitsPerValue, new common.BigInt("2"));
//         let Comms = [];
//         let gammas = [];
//         let aLConcat = [];
//         let aRConcat = [];
//         // let sumRand = new common.BigInt("0");
//         for (let j=0;j<this.Values.length;j++){
//             let v = this.Values[j];
//             if(v.cmp(new common.BigInt("0"))=== -1){
//                 return null
//             }
//             if (v.cmp(new common.BigInt(constants.MaxValue.toString(10),10))===1){
//                 return null
//             }
//             // let gamma = utils.RandInt(32);
//             let gamma = new common.BigInt("123456789").mul(new common.BigInt(j+1));
//             Comms[j] = rangeProofParams.G.mul(v).add(rangeProofParams.H.mul(gamma));
//             gammas[j] = gamma;
//             this.Rands[j] = gamma;
//             // break up v into its bitwise representation
//             let aL = bal_utils.reverse(bal_utils.StrToBigIntArray(bal_utils.PadLeft(v.toString(2,null),"0",bitsPerValue)));
//             let aR = bal_utils.VectorAddScalar(aL,new common.BigInt(-1));
//             for (let i =0;i<aR.length;i++){
//                 aLConcat[bitsPerValue*j+i] = aL[i];
//                 aRConcat[bitsPerValue*j+i] = aR[i];
//             }
//         }
//         MRProof.Comms = Comms;
//         this.Comms = Comms;
//         // console.log(Comms);
//         let alpha  = utils.RandInt(32);
//         let A = bal_utils.TwoVectorPCommitWithGens(rangeProofParams.BPG, rangeProofParams.BPH, aLConcat, aRConcat);
//         A = A.add(rangeProofParams.H.mul(alpha));
//         if (A===null){
//             return null;
//         }
//         else{
//             MRProof.A = A;
//         }
//         let sL = bal_utils.RandVector(rangeProofParams.V);
//         let sR = bal_utils.RandVector(rangeProofParams.V);
//         let rho = utils.RandInt(32);
//         let S = bal_utils.TwoVectorPCommitWithGens(rangeProofParams.BPG, rangeProofParams.BPH,aLConcat, aRConcat);
//         S = S.add(rangeProofParams.H.mul(alpha));
//         if (S===null){
//             return null;
//         }
//         else{
//             MRProof.S = S;
//         }
//         console.log(A);
//         let hashdata1 = A.getX().toString(10,null) + A.getY().toString(10,null);
//         let chal1s256 = common.HashBytesToBytes(utils.stringToBytes(hashdata1));
//         MRProof.Cy = utils.ByteArrToInt(chal1s256);
//
//         let hashdata2 = S.getX().toString(10,null) + S.getX().toString(10,null);
//         let chal2s256 = common.HashBytesToBytes(utils.stringToBytes(hashdata2));
//         MRProof.Cz = utils.ByteArrToInt(chal2s256);
//
//         let zPowersTimesTwoVec = [];
//         for (let j = 0; j < m; j++) {
//             let challengeZ = MRProof.Cz;
//             let zp = challengeZ.pow(new common.BigInt((2+j).toString(10),10));
//             zp = zp.umod(Curve.n);
//             for (let i = 0; i < bitsPerValue; i++) {
//                 let tmp = PowerOfTwos[i];
//                 zPowersTimesTwoVec[j*bitsPerValue+i] = tmp.mul(zp).umod(Curve.n);
//             }
//         }
//         let PowerOfCy = bal_utils.PowerVector(rangeProofParams.V, MRProof.Cy);
//         let l0 = bal_utils.VectorAddScalar(aLConcat, MRProof.Cz.neg());
//         let l1 = sL;
//         let r0 = bal_utils.VectorAdd(bal_utils.VectorHadamard(PowerOfCy,bal_utils.VectorAddScalar(aRConcat, MRProof.Cz)),zPowersTimesTwoVec);
//         let r1 = bal_utils.VectorHadamard(sR,PowerOfCy);
//         //calculate t0
//         let vz2 = new common.BigInt("0");
//         let cz = MRProof.Cz;
//         let z2 = cz.mul(cz).umod(Curve.n);
//         let PowerOfCz = bal_utils.PowerVector(m, MRProof.Cz);
//         for (let j=0;j<m;j++){
//             vz2 = vz2.add(PowerOfCz[j].mul(this.Values[j].mul(z2)));
//             vz2 = vz2.umod(Curve.n);
//         }
//         let t0 = vz2.add(bal_utils.DeltaMRP(PowerOfCy,MRProof.Cz,m,rangeProofParams));
//         t0 = t0.umod(Curve.n);
//         let t1 = bal_utils.InnerProduct(l1,r0);
//         t1 = t1.add(bal_utils.InnerProduct(l0,r1));
//         t1 = t1.umod(Curve.n);
//         let t2 = bal_utils.InnerProduct(l1,r1);
//         if (t2==null){
//             return null;
//         }
//         // given the t_i values, we can generate commitments to them
//         let tau1 = utils.RandInt(32);
//         let tau2 = utils.RandInt(32);
//         let T1 = rangeProofParams.G.mul(t1).add(rangeProofParams.H.mul(tau1));
//         let T2 = rangeProofParams.G.mul(t2).add(rangeProofParams.H.mul(tau2));
//         MRProof.T1 = T1;
//         MRProof.T2 = T2;
//
//         let hashdata3 = T1.getX().toString(10,null) + T1.getX().toString(10,null)+ T2.getX().toString(10,null) + T2.getX().toString(10,null);
//         let chal3p256 = common.HashBytesToBytes(utils.stringToBytes(hashdata3));
//         MRProof.Cx = utils.ByteArrToInt(chal2s256);
//
//         let left = bal_utils.CalculateLMRP(aLConcat,sL,MRProof.Cz, MRProof.Cx);
//         let right = bal_utils.CalculateRMRP(aRConcat,sR,PowerOfCy,zPowersTimesTwoVec, MRProof.Cz, MRProof.Cx);
//
//         // t0 + t1*x + t2*x^2
//         let t1MulX = t1.mul(MRProof.Cx);
//         let t2MulSqrX = t2.mul(MRProof.Cx).mul(MRProof.Cx);
//         let thatPrime = t0.add(t1MulX).add(t2MulSqrX);
//         thatPrime = thatPrime.umod(Curve.n);
//         let that = bal_utils.InnerProduct(left,right);
//         that = that.umod(Curve.n);
//         // console.log(that.toString(10,null), thatPrime.toString(10,null), Curve.n.toString(10,null));
//         // if (that.cmp(thatPrime)!==0){
//         //     return null
//         // }
//         return MRProof
//     }
//
// }
// function Test() {
//     let l = 5;
//     let V = [];
//
//     // for (let i=0;i<l;i++){
//     //     V[i] = utils.RandInt(8)
//     //    // console.log(V[i].toString(10, ""))
//     // }
//     V[0] = new common.BigInt("6755345518420511111",10);
//     V[1] = new common.BigInt("3694924673900965606",10);
//
//     a = new AggregatedRangeWitness();
//     a.set(V,64);
//     // console.log(a);
//     proof = a.prove();
//     console.log(proof)
// }
// // Test()
// // console.log(new MultiRangeProof());
// // console.log(new MultiRangeWitness());
// // x = new bal_utils.CryptoParams().InitCryptoParams(4,64).BPH
// // y = new bal_utils.CryptoParams().InitCryptoParams(4,64).H;
// // console.log(x.getX().toString(10,null),x.getY().toString(10,null));
// // for (let i=0;i<x.length;i++){
// //     console.log("&{"+x[i].getX().toString(10,null),x[i].getY().toString(10,null)+"}");
// // }
//
// // x = Curve.curve.point(new common.BigInt("220972225210613587092803207004116645329725881335810831594666496175168808161"),new common.BigInt("47109726179636173975559935971973816499842974684167213985561799433310741900221"));
// // console.log(x.getX().toString(10,null),x.getY().toString(10,null));
// // y = x.hash(0);
// // console.log(x.hash(0).getX().toString(10,null),x.hash(0).getY().toString(10,null));
// //
// // z = Curve.curve.point(new common.BigInt("36151787796040926116474505734917038331733277882630097517119716008390589266476"),new common.BigInt("97225466038482204218083683873444136647031569327106994981785194666182351853594"));
// // console.log(y.add(z));
//
//
// // var pedCom = require('../pedersen');
// // var constant = require('../constants');
// // console.log(pedCom.PedCom.G[constant.SND].getX().toString(10,null),pedCom.PedCom.G[constant.SND].getY().toString(10,null));
//
module.exports = { AggregatedRangeProof, AggregatedRangeWitness};