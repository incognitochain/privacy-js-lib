let common = require("../common");
let Curve = require("../ec").P256;
let utils = require('../privacy_utils');
let bal_utils = require("./aggregatedrange_utils");
let constants = require('../constants');
let params = require("./aggregaterangeparams");
let PedCom = require("../pedersen").PedCom;


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
    Bytes(){
        let l = 1;
        for (let i=0;i<this.cmsValue.length;i++){
            l = l +  constants.CompressPointSize
        }
        let innerProBytes = this.innerProductProof.Bytes();
        l = l + constants.CompressPointSize*4 + constants.BigIntSize*3 + innerProBytes.length;
        let bytes = new Uint8Array(l);
        let offset = 1;
        bytes.set([this.cmsValue.length],0);
        for (let i=0;i<this.cmsValue.length;i++){
            bytes.set(this.cmsValue[i].compress(), offset);
            offset = offset + constants.CompressPointSize;
        }
        bytes.set(this.A.compress(), offset);
        // console.log(this.A.compress());
        // console.log(Curve.isOnCurve(this.A));
        offset+=constants.CompressPointSize;
        bytes.set(this.S.compress(),offset);
        offset+=constants.CompressPointSize;
        bytes.set(this.T1.compress(),offset);
        offset+=constants.CompressPointSize;
        bytes.set(this.T2.compress(), offset);
        offset+=constants.CompressPointSize;
        bytes.set(this.tauX.toArray("be", constants.BigIntSize),offset);
        offset+=constants.BigIntSize;
        bytes.set(this.tHat.toArray("be", constants.BigIntSize),offset);
        offset+=constants.BigIntSize;
        bytes.set(this.mu.toArray("be", constants.BigIntSize),offset);
        offset+=constants.BigIntSize;
        bytes.set(innerProBytes,offset);
        return bytes;
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
        for (let i = 0; i < numValue; i++) {
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
            proof.cmsValue[i] = Curve.curve.point(0, 0)
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
        let z = params.generateChallengeForAggRange(AggParam, [A.compress(), S.compress(), y.toArray("be")]);
        let zNeg = z.neg();
        zNeg = zNeg.umod(Curve.n);
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
        innerProduct1 = innerProduct1.umod(Curve.n);
        deltaYZ = deltaYZ.mul(innerProduct1);

        // innerProduct2 = <1^n, 2^n>
        let innerProduct2 = new common.BigInt("0");
        for (let i=0;i<vector2powN.length;i++){
            innerProduct2 = innerProduct2.add(vector2powN[i])
        }
        innerProduct2 = innerProduct2.umod(Curve.n);

        let sum = new common.BigInt("0");
        zTmp = zSquare;
        for (let j=0;j<numValuePad;j++){
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(Curve.n);
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

        proof.T1 = PedCom.CommitAtIndex(t1, tau1,constants.VALUE);
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

// let numValue = 3;
// let values = [];
// let rands  = [];
// for (let i=0;i<numValue;i++){
//     values[i] = new common.BigInt("10");
//     rands[i] = utils.RandScalar(8);
// }
// let wit = new AggregatedRangeWitness(values,rands);
// let proof = wit.Prove();
// // proof.Print();
// // proof.IsSafe()
// let bytes = proof.Bytes();
// let bstr = "{";
// for (let b in bytes){
//     bstr += bytes[b].toString() + ","
// }
// let pos = bstr.length - 1
// bstr.replace(',', '}', pos);
// console.log(bstr);

































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
// // let pedCom = require('../pedersen');
// // let constant = require('../constants');
// // console.log(pedCom.PedCom.G[constant.SND].getX().toString(10,null),pedCom.PedCom.G[constant.SND].getY().toString(10,null));
//
module.exports = { AggregatedRangeProof, AggregatedRangeWitness};