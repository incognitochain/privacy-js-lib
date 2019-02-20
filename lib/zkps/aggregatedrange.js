let BigInt = require('bn.js');
let p256 = require("../ec").P256;
let utils = require('../privacy_utils');
let aggUtils = require("./aggregatedrange_utils");
let constants = require('../constants');
let params = require("./aggregaterangeparams");
let PedCom = require("../pedersen").PedCom;
class AggregatedRangeProof {
    constructor() {
        this.cmsValue = [];
        this.A = p256.curve.point(0, 0);
        this.S = p256.curve.point(0, 0);
        this.T1 = p256.curve.point(0, 0);
        this.T2 = p256.curve.point(0, 0);
        this.tauX = new BigInt("0");
        this.tHat = new BigInt("0");
        this.mu = new BigInt("0");
        this.innerProductProof = new aggUtils.innerProductProof()
    }

    bytes() {
        let l = 1 + constants.COMPRESS_POINT_SIZE * this.cmsValue.length;
        let innerProBytes = this.innerProductProof.bytes();
        l = l + constants.COMPRESS_POINT_SIZE * 4 + constants.BIG_INT_SIZE * 3 + innerProBytes.length;
        let bytes = new Uint8Array(l);
        let offset = 1;
        bytes.set([this.cmsValue.length], 0);
        for (let i = 0; i < this.cmsValue.length; i++) {
            bytes.set(this.cmsValue[i].compress(), offset);
            offset = offset + constants.COMPRESS_POINT_SIZE;
        }
        bytes.set(this.A.compress(), offset);
        offset += constants.COMPRESS_POINT_SIZE;
        bytes.set(this.S.compress(), offset);
        offset += constants.COMPRESS_POINT_SIZE;
        bytes.set(this.T1.compress(), offset);
        offset += constants.COMPRESS_POINT_SIZE;
        bytes.set(this.T2.compress(), offset);
        offset += constants.COMPRESS_POINT_SIZE;
        bytes.set(this.tauX.toArray("be", constants.BIG_INT_SIZE), offset);
        offset += constants.BIG_INT_SIZE;
        bytes.set(this.tHat.toArray("be", constants.BIG_INT_SIZE), offset);
        offset += constants.BIG_INT_SIZE;
        bytes.set(this.mu.toArray("be", constants.BIG_INT_SIZE), offset);
        offset += constants.BIG_INT_SIZE;
        bytes.set(innerProBytes, offset);
        return bytes;
    }

    verify() {
        let numValue = proof.cmsValue.length;
        let numValuePad = aggUtils.pad(numValue);
        for (let i = numValue; i < numValuePad; i++) {
            this.cmsValue.push(p256.curve.point(0, 0));
        }
        let aggParam = new params.BulletproofParams(numValuePad);
        let n = constants.MAX_EXP;

        let numberTwo = new BigInt("2");
        let vectorMinusOne = [];
        for (let i = 0; i < n * numValuePad; i++) {
            vectorMinusOne[i] = new BigInt("-1")
        }
        let vector2powN = aggUtils.powerVector(numberTwo, n);
        // recalculate challenge y, z
        let y = params.generateChallengeForAggRange(aggParam, [this.A.compress(), this.S.compress()]);
        let z = params.generateChallengeForAggRange(aggParam, [this.A.compress(), this.S.compress(), y.toArray("be")]);
        let zNeg = z.neg();
        zNeg = zNeg.umod(p256.n);
        let zSquare = z.mul(z);
        z = z.umod(p256.n);

        // challenge x = hash(G || H || A || S || T1 || T2)
        let x = params.generateChallengeForAggRange(aggParam, [proof.A.compress(), proof.S.compress(), proof.T1.compress(), proof.T2.compress()])
        let xSquare = x.mul(x);
        xSquare = xSquare.umod(p256.n);
        let vectorPowOfY = aggUtils.powerVector(y, n * numValuePad);

        let HPrime = [];
        for (let i = 0; i < n * numValuePad; i++) {
            let yPowMinusOne = y.pow(new BigInt(-i));
            yPowMinusOne.umod(p256.n);
            HPrime[i] = aggParam.H[i].mul(yPowMinusOne);
        }
        // g^tHat * h^tauX = V^(z^2) * g^delta(y,z) * T1^x * T2^(x^2)
        let deltaYZ = z.sub(zSquare);
        let innerProduct1 = new BigInt("0");
        // innerProduct1 = <1^(n*m), y^(n*m)>
        for (let i = 0; i < vectorPowOfY.length; i++) {
            innerProduct1 = innerProduct1.add(vectorPowOfY[i])
        }
        innerProduct1 = innerProduct1.umod(p256.n);
        deltaYZ = deltaYZ.mul(innerProduct1);

        // innerProduct2 = <1^n, 2^n>
        let innerProduct2 = new BigInt("0");
        for (let i = 0; i < vector2powN.length; i++) {
            innerProduct2 = innerProduct2.add(vector2powN[i])
        }
        innerProduct2 = innerProduct2.umod(p256.n);

        let sum = new BigInt("0");
        let zTmp = zSquare;
        for (let j = 0; j < numValuePad; j++) {
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(p256.n);
            sum = sum.add(zTmp);
        }
        sum = sum.mul(innerProduct2);
        deltaYZ = deltaYZ.sub(sum);
        deltaYZ = deltaYZ.umod(p256.n);

        let left = PedCom.commitAtIndex(this.tHat, this.tauX, constants.VALUE);
        let right = PedCom.G[constants.VALUE].mul(deltaYZ).add(this.T1.mul(x)).add(this.T2.mul(xSquare));
        let expVector = aggUtils.vectorMulScalar(aggUtils.powerVector(z, numValuePad), zSquare);
        for (let i = 0; i < this.cmsValue.length; i++) {
            right = right.add(this.cmsValue[i].mul(expVector[i]))
        }
        if (left.getX().cmp(right.getX()) !== 0 && left.getY().cmp(right.getY()) !== 0) {
            return false;
        }
        return this.innerProductProof.verify(aggParam)
    }
}
class AggregatedRangeWitness {
    constructor() {
        this.values = [];
        this.rands = [];
    }

    set(values, rands){
        let numValue = values.length;
        this.values = [];
        this.rands = [];
        for (let i = 0; i < numValue; i++) {
            this.values[i] = values[i];
            this.rands[i] = rands[i];
        }
    }

    prove() {
        let proof = new AggregatedRangeProof();
        let numValue = this.values.length;
        let numValuePad = aggUtils.pad(numValue);
        let values = [];
        let rands = [];
        for (let i = 0; i < numValue; i++) {
            values[i] = this.values[i];
            rands[i] = this.rands[i];
        }
        for (let i = numValue; i < numValuePad; i++) {
            values[i] = new BigInt("0");
            rands[i] = new BigInt("0");
        }
        let AggParam = new params.BulletproofParams(numValuePad);
        proof.cmsValue = [];
        for (let i = 0; i < numValue; i++) {
            proof.cmsValue[i] = PedCom.commitAtIndex(values[i], rands[i], constants.VALUE)
        }
        let n = constants.MAX_EXP;
        let aL = [];
        for (let i = 0; i < values.length; i++) {
            let tmp = utils.convertIntToBinary(values[i], n);
            for (let j = 0; j < n; j++) {
                aL[i * n + j] = new BigInt(tmp[j])
            }
        }
        let numberTwo = new BigInt("2");
        let vectorMinusOne = [];
        for (let i = 0; i < n * numValuePad; i++) {
            vectorMinusOne[i] = new BigInt("-1")
        }
        let vector2powN = aggUtils.powerVector(numberTwo, n);
        let aR = aggUtils.vectorAdd(aL, vectorMinusOne);
        let alpha = utils.randScalar();
        let A = params.EncodeVectors(aL, aR, AggParam.G, AggParam.H);
        A = A.add(PedCom.G[constants.RAND].mul(alpha));
        proof.A = A;
        // Random blinding vectors sL, sR
        let sL = [];
        let sR = [];
        for (let i = 0; i < n * numValuePad; i++) {
            sL[i] = utils.randScalar();
            sR[i] = utils.randScalar();
        }
        let rho = utils.randScalar();
        let S = params.EncodeVectors(sL, sR, AggParam.G, AggParam.H);
        S = S.add(PedCom.G[constants.RAND].mul(rho));
        proof.S = S;

        // challenge y, z
        let y = params.generateChallengeForAggRange(AggParam, [A.compress(), S.compress()]);
        let z = params.generateChallengeForAggRange(AggParam, [A.compress(), S.compress(), y.toArray("be")]);
        let zNeg = z.neg();
        zNeg = zNeg.umod(p256.n);
        let zSquare = z.mul(z);
        zSquare = zSquare.umod(p256.n);
        let vectorPowOfY = aggUtils.powerVector(y, n * numValuePad);
        let l0 = aggUtils.vectorAddScalar(aL, zNeg);

        let l1 = sL;
        // r(X) = y^n hada (aR +z*1^n + sR*X) + z^2 * 2^n
        let hadaProduct = aggUtils.hadamardProduct(vectorPowOfY, aggUtils.vectorAddScalar(aR, z));


        let vectorSum = [];
        let zTmp = z;
        for (let j = 0; j < numValuePad; j++) {
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(p256.n);
            for (let i = 0; i < n; i++) {
                vectorSum[j * n + i] = vector2powN[i].mul(zTmp);
                vectorSum[j * n + i] = vectorSum[j * n + i].umod(p256.n);
            }
        }

        let r0 = aggUtils.vectorAdd(hadaProduct, vectorSum);
        let r1 = aggUtils.hadamardProduct(vectorPowOfY, sR);
        //t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2
        let deltaYZ = z.sub(zSquare);


        let innerProduct1 = new BigInt("0");
        // innerProduct1 = <1^(n*m), y^(n*m)>
        for (let i = 0; i < vectorPowOfY.length; i++) {
            innerProduct1 = innerProduct1.add(vectorPowOfY[i])
        }
        innerProduct1 = innerProduct1.umod(p256.n);
        deltaYZ = deltaYZ.mul(innerProduct1);

        // innerProduct2 = <1^n, 2^n>
        let innerProduct2 = new BigInt("0");
        for (let i = 0; i < vector2powN.length; i++) {
            innerProduct2 = innerProduct2.add(vector2powN[i])
        }
        innerProduct2 = innerProduct2.umod(p256.n);

        let sum = new BigInt("0");
        zTmp = zSquare;
        for (let j = 0; j < numValuePad; j++) {
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(p256.n);
            sum = sum.add(zTmp);
        }
        sum = sum.mul(innerProduct2);
        deltaYZ = deltaYZ.sub(sum);
        deltaYZ = deltaYZ.umod(p256.n);

        // t1 = <l1, r0> + <l0, r1>
        let innerProduct3 = aggUtils.innerProduct(l1, r0);
        let innerProduct4 = aggUtils.innerProduct(l0, r1);
        let t1 = innerProduct3.add(innerProduct4);
        t1 = t1.umod(p256.n);
        let t2 = aggUtils.innerProduct(l1, r1);

        // commitment to t1, t2
        let tau1 = utils.randScalar();
        let tau2 = utils.randScalar();

        proof.T1 = PedCom.commitAtIndex(t1, tau1, constants.VALUE);
        proof.T2 = PedCom.commitAtIndex(t2, tau2, constants.VALUE);

        // challenge x = hash(G || H || A || S || T1 || T2)

        let x = params.generateChallengeForAggRange(AggParam, [proof.A.compress(), proof.S.compress(), proof.T1.compress(), proof.T2.compress()])
        let xSquare = x.mul(x);
        xSquare = xSquare.umod(p256.n);

        // lVector = aL - z*1^n + sL*x
        let lVector = aggUtils.vectorAdd(aggUtils.vectorAddScalar(aL, zNeg), aggUtils.vectorMulScalar(sL, x));
        // rVector = y^n hada (aR +z*1^n + sR*x) + z^2*2^n
        let tmpVector = aggUtils.vectorAdd(aggUtils.vectorAddScalar(aR, z), aggUtils.vectorMulScalar(sR, x));
        let rVector = aggUtils.hadamardProduct(vectorPowOfY, tmpVector);
        vectorSum = [];
        zTmp = z;
        for (let j = 0; j < numValuePad; j++) {
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(p256.n);
            for (let i = 0; i < n; i++) {
                vectorSum[j * n + i] = vector2powN[i].mul(zTmp);
                vectorSum[j * n + i] = vectorSum[j * n + i].umod(p256.n);
            }
        }
        rVector = aggUtils.vectorAdd(rVector, vectorSum);
        // tHat = <lVector, rVector>
        proof.tHat = aggUtils.innerProduct(lVector, rVector);
        // blinding value for tHat: tauX = tau2*x^2 + tau1*x + z^2*rand
        proof.tauX = tau2.mul(xSquare);
        proof.tauX = proof.tauX.add(tau1.mul(x));
        zTmp = z;
        for (let j = 0; j < numValuePad; j++) {
            zTmp = zTmp.mul(z);
            zTmp = zTmp.umod(p256.n);
            proof.tauX = proof.tauX.add(zTmp.mul(rands[j]))
        }
        proof.tauX = proof.tauX.umod(p256.n);
        // alpha, rho blind A, S
        // mu = alpha + rho*x
        proof.mu = rho.mul(x);
        proof.mu = proof.mu.add(alpha);
        proof.mu = proof.mu.umod(p256.n);

        // instead of sending left vector and right vector, we use inner sum argument to reduce proof size from 2*n to 2(log2(n)) + 2
        let innerProductWit = new aggUtils.innerProductWitness();
        innerProductWit.a = lVector;
        innerProductWit.b = rVector;
        innerProductWit.p = params.EncodeVectors(lVector, rVector, AggParam.G, AggParam.H);


        innerProductWit.p = innerProductWit.p.add(AggParam.U.mul(proof.tHat));

        proof.innerProductProof = innerProductWit.prove(AggParam);
        return proof
    }
}

// let numValue = 1;
// let values = [];
// let rands = [];
// for (let i = 0; i < numValue; i++) {
//     values[i] = new BigInt("10");
//     rands[i] = utils.randScalar(8);
// }
// let wit = new AggregatedRangeWitness(values, rands);
// let proof = wit.prove();
// console.log(proof.verify());
// // proof.Print();
// // proof.IsSafe()
// let bytes = proof.bytes();
// let bstr = "{";
// for (let b in bytes){
//     bstr += bytes[b].toString() + ","
// }
// let pos = bstr.length - 1;
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
//     V[0] = new BigInt("6755345518420511111",10);
//     V[1] = new BigInt("3694924673900965606",10);
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
// // x = p256.p256.point(new BigInt("220972225210613587092803207004116645329725881335810831594666496175168808161"),new BigInt("47109726179636173975559935971973816499842974684167213985561799433310741900221"));
// // console.log(x.getX().toString(10,null),x.getY().toString(10,null));
// // y = x.hash(0);
// // console.log(x.hash(0).getX().toString(10,null),x.hash(0).getY().toString(10,null));
// //
// // z = p256.p256.point(new BigInt("36151787796040926116474505734917038331733277882630097517119716008390589266476"),new BigInt("97225466038482204218083683873444136647031569327106994981785194666182351853594"));
// // console.log(y.add(z));
//
//
// // let pedCom = require('../pedersen');
// // let constant = require('../constants');
// // console.log(pedCom.PedCom.G[constant.SND].getX().toString(10,null),pedCom.PedCom.G[constant.SND].getY().toString(10,null));
//
module.exports = {
    AggregatedRangeProof,
    AggregatedRangeWitness
};