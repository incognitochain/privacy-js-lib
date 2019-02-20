let BigInt = require('bn.js');
let p256 = require("../ec").P256;
let utils = require('../privacy_utils');
let aggUtils = require("./aggregatedrange_utils");
let constants = require('../constants');
let params = require("./aggregaterangeparams");
let PedCom = require("../pedersen").PedCom;

class aggregatedRangeProof {
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
        let l = 1 + constants.CompressPointSize * this.cmsValue.length;
        let innerProBytes = this.innerProductProof.bytes();
        l = l + constants.CompressPointSize * 4 + constants.BigIntSize * 3 + innerProBytes.length;
        let bytes = new Uint8Array(l);
        let offset = 1;
        bytes.set([this.cmsValue.length], 0);
        for (let i = 0; i < this.cmsValue.length; i++) {
            bytes.set(this.cmsValue[i].compress(), offset);
            offset = offset + constants.CompressPointSize;
        }
        bytes.set(this.A.compress(), offset);
        offset += constants.CompressPointSize;
        bytes.set(this.S.compress(), offset);
        offset += constants.CompressPointSize;
        bytes.set(this.T1.compress(), offset);
        offset += constants.CompressPointSize;
        bytes.set(this.T2.compress(), offset);
        offset += constants.CompressPointSize;
        bytes.set(this.tauX.toArray("be", constants.BigIntSize), offset);
        offset += constants.BigIntSize;
        bytes.set(this.tHat.toArray("be", constants.BigIntSize), offset);
        offset += constants.BigIntSize;
        bytes.set(this.mu.toArray("be", constants.BigIntSize), offset);
        offset += constants.BigIntSize;
        bytes.set(innerProBytes, offset);
        return bytes;
    }

    setBytes(bytes) {
        if (bytes.length === 0) {
            return null;
        }
        let lenValues = bytes[0];
        let offset = 1;
        this.cmsValue = [];
        for (let i = 0; i < lenValues; i++) {
            this.cmsValue[i] = p256.decompress(bytes.slice(offset, offset + constants.CompressPointSize));
            offset = offset + constants.CompressPointSize;
        }
        this.A = p256.decompress(bytes.slice(offset, offset + constants.CompressPointSize));
        offset = offset + constants.CompressPointSize;

        this.S = p256.decompress(bytes.slice(offset, offset + constants.CompressPointSize));
        offset = offset + constants.CompressPointSize;

        this.T1 = p256.decompress(bytes.slice(offset, offset + constants.CompressPointSize));
        offset = offset + constants.CompressPointSize;

        this.T2 = p256.decompress(bytes.slice(offset, offset + constants.CompressPointSize));
        offset = offset + constants.CompressPointSize;

        this.tauX = new BigInt(bytes.slice(offset, offset + constants.BigIntSize), 16, "be");
        offset = offset + constants.BigIntSize;

        this.tHat = new BigInt(bytes.slice(offset, offset + constants.BigIntSize), 16, "be");
        offset = offset + constants.BigIntSize;

        this.mu = new BigInt(bytes.slice(offset, offset + constants.BigIntSize), 16, "be");
        offset = offset + constants.BigIntSize;

        this.innerProductProof.setBytes(bytes.slice(offset,));
    }
    verify() {
        let numValue = this.cmsValue.length;
        let numValuePad = aggUtils.pad(numValue);
        for (let i = numValue; i < numValuePad; i++) {
            this.cmsValue.push(p256.curve.point(0, 0));
        }
        let aggParam = new params.BulletproofParams(numValuePad);
        let n = constants.MaxEXP;

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
        let x = params.generateChallengeForAggRange(aggParam, [this.A.compress(), this.S.compress(), this.T1.compress(), this.T2.compress()]);
        let xSquare = x.mul(x);
        xSquare = xSquare.umod(p256.n);
        let vectorPowOfY = aggUtils.powerVector(y, n * numValuePad);

        let HPrime = [];
        for (let i = 0; i < n * numValuePad; i++) {
            let yPowMinusOne = y.pow(new BigInt(-i));
            // yPowMinusOne.invm(p256.n);
            HPrime[i] = aggParam.H[i].mul(yPowMinusOne);
            console.log(i, HPrime[i].getX().toString(), HPrime[i].getY().toString());

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

class aggregatedRangeWitness {
    constructor(values, rands) {
        let numValue = values.length;
        this.values = [];
        this.rands = [];
        for (let i = 0; i < numValue; i++) {
            this.values[i] = values[i];
            this.rands[i] = rands[i];
        }
    }

    prove() {
        let proof = new aggregatedRangeProof();
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
            proof.cmsValue[i] = PedCom.commitAtIndex(values[i], rands[i], constants.VALUE);
        }
        let n = constants.MaxEXP;
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


        for (let i = 0; i < AggParam.G.length; i++) {
            console.log(AggParam.G[i].getX().toString(), AggParam.G[i].getY().toString());
        }
        console.log("----------------")
        for (let i = 0; i < AggParam.G.length; i++) {
            console.log(AggParam.H[i].getX().toString(), AggParam.H[i].getY().toString());
        }
        console.log("----------------")


        console.log(A.getX().toString(), A.getY().toString());

        A = A.add(PedCom.G[constants.RAND].mul(alpha));
        proof.A = A;
        console.log(proof.A.getX().toString(), proof.A.getY().toString());
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

let numValue = 1;
let values = [];
let rands = [];
for (let i = 0; i < numValue; i++) {
    values[i] = new BigInt("10");
    rands[i] = utils.randScalar(8);
}
let wit = new aggregatedRangeWitness(values, rands);
let proof = wit.prove();

// let proof = new aggregatedRangeProof();
// let proofBytes =
//     [3,2,122,107,16,54,19,89,32,207,107,136,47,29,43,19,15,236,12,20,213,37,231,240,103,166,240,150,218,149,37,46,65,107,2,82,186,169,251,185,126,33,96,223,155,213,92,168,205,46,53,81,35,109,163,150,214,239,101,81,37,110,35,77,140,1,135,2,41,105,143,10,34,17,166,204,30,148,249,8,162,225,205,254,236,40,158,113,83,231,224,200,159,102,8,208,171,66,51,216,2,228,202,49,148,12,165,147,14,124,177,249,55,33,31,114,199,13,255,224,23,232,77,58,189,4,221,237,117,184,228,146,41,3,119,231,134,237,154,44,217,233,222,40,61,193,216,250,53,27,31,242,57,143,53,28,222,72,240,189,49,103,239,236,220,174,3,38,173,1,217,224,96,177,187,60,253,242,146,105,157,193,89,196,49,245,252,19,115,226,116,25,8,118,57,101,73,165,243,3,150,98,126,173,146,52,180,214,228,174,86,42,56,76,119,204,219,82,200,109,248,59,29,7,70,12,186,64,184,233,239,250,220,40,202,218,91,34,4,241,228,185,163,35,102,87,192,16,204,30,185,171,75,86,141,171,219,53,230,50,105,124,145,234,91,30,72,88,153,221,210,85,59,50,104,252,139,106,199,74,153,164,152,203,88,253,236,139,98,110,107,187,188,49,143,12,167,67,32,238,129,70,3,35,209,200,45,128,186,117,9,30,43,128,230,48,238,173,225,227,124,207,138,236,63,252,235,161,8,3,127,79,189,184,185,36,193,18,194,252,31,40,160,243,86,29,218,216,143,241,219,195,47,68,6,67,213,230,129,157,222,169,3,10,8,188,173,138,145,137,249,132,231,107,60,191,39,82,239,197,47,126,125,137,179,108,44,163,164,18,239,110,23,91,223,2,179,206,233,86,165,49,238,128,154,241,156,233,193,128,43,186,36,79,103,229,120,157,219,24,179,42,66,113,63,238,226,77,3,110,58,116,10,249,3,136,167,243,145,15,154,54,231,216,68,99,24,21,7,54,228,3,96,88,230,5,61,10,89,56,16,2,2,248,14,33,180,117,51,152,11,13,186,220,167,151,125,159,75,141,178,163,2,34,189,156,253,181,31,187,142,186,39,33,2,132,152,160,32,179,160,217,156,162,244,152,165,55,115,38,37,165,223,138,225,105,87,135,236,243,185,202,81,161,71,26,93,2,103,72,151,32,214,143,117,95,233,191,3,250,219,40,181,147,23,92,53,100,153,195,156,17,28,199,205,0,60,201,191,58,2,125,71,172,54,84,50,172,57,203,0,248,55,54,242,95,223,102,106,17,255,15,142,207,102,6,219,252,114,155,172,11,190,3,24,68,2,151,37,151,37,188,140,51,62,150,226,248,87,72,84,54,27,203,105,31,46,207,204,237,245,113,16,79,25,143,2,34,166,23,188,71,191,58,74,83,163,136,197,211,120,17,207,76,244,8,202,192,104,159,51,69,154,136,163,188,11,148,202,3,98,245,101,248,44,168,85,158,78,178,18,160,134,211,55,84,97,114,210,236,139,175,174,58,87,43,95,235,127,151,51,201,3,6,23,110,115,223,244,72,75,234,35,232,38,14,249,129,177,192,222,94,64,159,236,161,137,143,27,167,140,74,174,105,193,3,185,48,19,187,182,89,160,173,48,172,220,210,41,213,38,215,252,38,180,152,131,134,218,135,113,166,175,251,228,15,81,69,3,231,39,154,161,31,9,13,37,210,157,129,200,43,168,207,125,47,135,91,150,29,116,207,66,105,15,20,149,82,101,2,194,3,177,181,198,197,57,44,167,117,188,200,175,197,153,172,149,212,244,153,205,149,165,125,29,140,190,216,200,46,4,163,42,190,2,47,255,175,26,201,22,171,227,116,195,62,254,13,33,236,189,50,219,203,101,210,181,111,25,254,56,195,41,160,159,138,119,9,196,149,132,9,193,197,134,237,253,39,117,82,44,183,40,217,129,125,24,255,136,76,157,229,180,88,4,104,245,250,42,97,30,164,188,170,143,198,166,223,212,143,41,157,167,191,14,213,124,57,203,65,223,72,84,186,14,60,171,111,69,68,233,2,222,82,114,144,94,174,162,145,213,111,96,226,203,24,26,75,152,204,82,136,96,171,120,196,225,13,116,158,159,139,138,234]
//
// proof.setBytes(proofBytes);

// console.log(proof.verify());
// console.log(proof.A.getX().toString(), proof.A.getY().toString());
// console.log(proof.S.getX().toString(), proof.S.getY().toString());
// console.log(proof.T1.getX().toString(), proof.T1.getY().toString());
// console.log(proof.T2.getX().toString(), proof.T2.getY().toString());
// console.log((proof.tauX.toString()));
// console.log((proof.tHat.toString()));
// console.log((proof.mu.toString()));
// console.log(proof.innerProductProof.a.toString());
// console.log(proof.innerProductProof.b.toString());
// console.log(proof.innerProductProof.p.getX().toString(),proof.innerProductProof.p.getY().toString())
// console.log("------------------")
// for (let i=0;i<proof.innerProductProof.l.length;i++){
//     console.log(proof.innerProductProof.l[i].getX().toString(),proof.innerProductProof.l[i].getY().toString())
//
// }
// console.log("------------------")
// for (let i=0;i<proof.innerProductProof.l.length;i++){
//     console.log(proof.innerProductProof.r[i].getX().toString(),proof.innerProductProof.r[i].getY().toString())
//
// }
// console.log(proof.innerProductProof.a.toString());
// console.log(proof.innerProductProof.b.toString());
// console.log(proof.innerProductProof.p.getX().toString(),proof.innerProductProof.p.getY().toString())

// // proof.Print();
// // proof.IsSafe()
let bytes = proof.bytes();
let bstr = "{";
for (let b in bytes) {
    bstr += bytes[b].toString() + ","
}
let pos = bstr.length - 1;
bstr.replace(',', '}', pos);
console.log(bstr);

































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
//     a = new aggregatedRangeWitness();
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
    aggregatedRangeProof,
    aggregatedRangeWitness
};