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

    setBytes(bytes) {
        if (bytes.length === 0) {
            return null;
        }
        let lenValues = bytes[0];
        let offset = 1;
        this.cmsValue = new Array(lenValues);
        for (let i = 0; i < lenValues; i++) {
            this.cmsValue[i] = p256.decompress(bytes.slice(offset, offset + constants.COMPRESS_POINT_SIZE));
            offset = offset + constants.COMPRESS_POINT_SIZE;
        }
        this.A = p256.decompress(bytes.slice(offset, offset + constants.COMPRESS_POINT_SIZE));
        offset = offset + constants.COMPRESS_POINT_SIZE;

        this.S = p256.decompress(bytes.slice(offset, offset + constants.COMPRESS_POINT_SIZE));
        offset = offset + constants.COMPRESS_POINT_SIZE;

        this.T1 = p256.decompress(bytes.slice(offset, offset + constants.COMPRESS_POINT_SIZE));
        offset = offset + constants.COMPRESS_POINT_SIZE;

        this.T2 = p256.decompress(bytes.slice(offset, offset + constants.COMPRESS_POINT_SIZE));
        offset = offset + constants.COMPRESS_POINT_SIZE;

        this.tauX = new BigInt(bytes.slice(offset, offset + constants.BIG_INT_SIZE), 16, "be");
        offset = offset + constants.BIG_INT_SIZE;

        this.tHat = new BigInt(bytes.slice(offset, offset + constants.BIG_INT_SIZE), 16, "be");
        offset = offset + constants.BIG_INT_SIZE;

        this.mu = new BigInt(bytes.slice(offset, offset + constants.BIG_INT_SIZE), 16, "be");
        offset = offset + constants.BIG_INT_SIZE;

        this.innerProductProof.setBytes(bytes.slice(offset,));
    }
    verify() {
        let numValue = this.cmsValue.length;
        let numValuePad = aggUtils.pad(numValue);
        for (let i = numValue; i < numValuePad; i++) {
            this.cmsValue.push(p256.curve.point(0, 0));
        }
        let aggParam = new params.BulletproofParams(numValuePad);
        let n = constants.MAX_EXP;

        let numberTwo = new BigInt("2");
        let vectorMinusOne = new Array(n * numValuePad);
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

        let HPrime = new Array(n * numValuePad);
        for (let i = 0; i < n * numValuePad; i++) {
            let yPowMinusOne = y.pow(new BigInt(i));
            yPowMinusOne = yPowMinusOne.invm(p256.n);
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

    }

    set(values, rands) {
        let numValue = values.length;
        this.values = new Array(numValue);
        this.rands = new Array(numValue);
        for (let i = 0; i < numValue; i++) {
            this.values[i] = values[i];
            this.rands[i] = rands[i];
        }
    }

    prove() {
        let proof = new AggregatedRangeProof();
        let numValue = this.values.length;
        let numValuePad = aggUtils.pad(numValue);
        let values = new Array(numValuePad);
        let rands = new Array(numValuePad);
        for (let i = 0; i < numValue; i++) {
            values[i] = this.values[i];
            rands[i] = this.rands[i];
        }
        for (let i = numValue; i < numValuePad; i++) {
            values[i] = new BigInt("0");
            rands[i] = new BigInt("0");
        }
        let AggParam = new params.BulletproofParams(numValuePad);
        proof.cmsValue = new Array(numValue);
        for (let i = 0; i < numValue; i++) {
            proof.cmsValue[i] = PedCom.commitAtIndex(values[i], rands[i], constants.VALUE);
        }
        let n = constants.MAX_EXP;
        let aL = new Array(numValuePad);
        for (let i = 0; i < values.length; i++) {
            let tmp = utils.convertIntToBinary(values[i], n);
            for (let j = 0; j < n; j++) {
                aL[i * n + j] = new BigInt(tmp[j])
            }
        }

        let numberTwo = new BigInt("2");
        let vectorMinusOne = new Array(numValuePad * n);
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
        let sL = new Array(numValuePad * n);
        let sR = new Array(numValuePad * n);
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


        let vectorSum = new Array(numValuePad * n);
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
        vectorSum = new Array(numValuePad * n);
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

//
// let numValue = 1;
// let values = [];
// let rands = [];
// for (let i = 0; i < numValue; i++) {
//     values[i] = new BigInt("10");
//     rands[i] = utils.randScalar(8);
// }
// let wit = new AggregatedRangeWitness(values, rands);
// let proof = wit.prove();
// // console.log(proof.bytes())
let proof1 = new AggregatedRangeProof();
let proofBytes =
    [1, 2, 27, 164, 42, 147, 128, 15, 216, 180, 97, 213, 149, 34, 5, 64, 212, 243, 131, 235, 130, 79, 240, 72, 196, 35, 213, 228, 141, 224, 226, 156, 119, 101, 2, 188, 188, 12, 241, 4, 225, 1, 19, 70, 12, 204, 133, 255, 41, 134, 242, 100, 255, 21, 75, 60, 191, 205, 87, 204, 129, 116, 222, 215, 138, 11, 48, 2, 190, 57, 43, 65, 238, 95, 11, 251, 101, 193, 205, 22, 238, 106, 198, 160, 63, 122, 153, 132, 207, 139, 214, 113, 74, 252, 94, 167, 26, 186, 61, 43, 3, 77, 24, 144, 133, 179, 101, 174, 127, 123, 80, 250, 145, 34, 13, 20, 17, 94, 136, 76, 160, 51, 196, 56, 120, 227, 249, 11, 67, 161, 189, 174, 132, 3, 152, 167, 153, 110, 19, 18, 42, 169, 209, 24, 0, 137, 156, 222, 82, 47, 56, 28, 232, 27, 180, 132, 172, 234, 16, 88, 238, 170, 22, 118, 166, 94, 208, 96, 188, 104, 156, 109, 239, 118, 98, 41, 130, 131, 4, 248, 70, 146, 140, 143, 254, 235, 3, 65, 234, 162, 231, 218, 63, 133, 193, 68, 142, 17, 117, 102, 157, 172, 110, 251, 42, 5, 37, 4, 105, 27, 221, 86, 42, 104, 103, 62, 138, 177, 250, 66, 35, 189, 155, 64, 25, 40, 173, 99, 141, 229, 147, 198, 206, 84, 195, 9, 19, 60, 51, 218, 36, 120, 189, 12, 219, 9, 114, 32, 173, 45, 240, 35, 174, 245, 222, 220, 75, 10, 74, 253, 35, 57, 6, 3, 241, 160, 244, 210, 252, 93, 200, 87, 212, 28, 159, 125, 19, 25, 196, 152, 202, 29, 115, 150, 206, 67, 168, 224, 53, 24, 109, 39, 135, 70, 156, 24, 3, 58, 216, 91, 64, 249, 27, 67, 129, 25, 231, 34, 141, 74, 190, 248, 66, 145, 11, 173, 155, 171, 81, 1, 177, 180, 168, 72, 14, 182, 91, 181, 31, 2, 140, 48, 189, 231, 29, 36, 210, 100, 5, 232, 213, 123, 97, 194, 69, 129, 1, 210, 57, 137, 5, 255, 181, 46, 7, 215, 248, 213, 221, 93, 139, 26, 2, 250, 235, 171, 218, 109, 226, 245, 122, 215, 101, 193, 108, 150, 67, 123, 70, 108, 96, 99, 246, 167, 170, 40, 16, 81, 28, 83, 176, 96, 103, 38, 22, 3, 171, 96, 166, 19, 132, 157, 48, 106, 126, 51, 53, 206, 20, 13, 13, 231, 216, 139, 204, 215, 24, 182, 100, 150, 214, 243, 222, 91, 58, 18, 80, 130, 3, 213, 128, 75, 172, 216, 61, 36, 193, 240, 13, 149, 70, 82, 101, 34, 181, 74, 220, 179, 119, 32, 148, 134, 152, 69, 175, 138, 219, 178, 200, 49, 196, 3, 224, 80, 9, 241, 98, 243, 83, 235, 199, 25, 131, 222, 181, 26, 193, 213, 80, 207, 35, 177, 118, 233, 118, 54, 222, 95, 102, 105, 39, 64, 110, 11, 2, 179, 87, 86, 182, 149, 132, 102, 158, 241, 42, 130, 169, 153, 16, 19, 101, 217, 242, 69, 211, 34, 57, 102, 57, 113, 116, 64, 143, 67, 130, 240, 122, 2, 230, 106, 226, 232, 98, 30, 40, 32, 242, 52, 137, 162, 98, 130, 14, 118, 66, 216, 223, 107, 96, 217, 15, 94, 159, 233, 68, 201, 156, 231, 40, 113, 2, 243, 134, 240, 92, 187, 163, 219, 136, 134, 50, 248, 186, 125, 92, 83, 221, 34, 198, 61, 126, 60, 6, 72, 77, 194, 79, 76, 176, 223, 36, 19, 32, 2, 128, 37, 201, 23, 72, 49, 45, 254, 71, 184, 75, 173, 90, 227, 210, 95, 125, 30, 208, 221, 77, 160, 230, 65, 137, 103, 108, 144, 254, 136, 171, 97, 3, 159, 208, 43, 115, 2, 68, 106, 10, 25, 164, 232, 18, 103, 161, 186, 58, 87, 76, 31, 21, 48, 61, 117, 192, 240, 1, 136, 158, 186, 132, 168, 200, 88, 19, 59, 241, 164, 116, 20, 250, 78, 204, 240, 237, 13, 130, 245, 58, 58, 201, 106, 252, 185, 192, 67, 209, 29, 159, 1, 105, 155, 184, 198, 108, 26, 31, 48, 78, 51, 69, 193, 106, 201, 222, 55, 117, 245, 233, 39, 144, 143, 121, 211, 113, 159, 153, 138, 197, 111, 189, 236, 166, 41, 19, 42, 182, 2, 63, 128, 208, 102, 90, 80, 110, 246, 1, 227, 241, 156, 237, 108, 88, 237, 18, 209, 114, 102, 13, 88, 101, 62, 53, 191, 106, 219, 179, 18, 27, 161]
//
proof1.setBytes(proofBytes);
//
console.log(proof1.verify());
// console.log(proof.A.getX().toString(), proof.A.getY().toString());
// console.log(proof.S.getX().toString(), proof.S.getY().toString());
// console.log(proof.T1.getX().toString(), proof.T1.getY().toString());
// console.log(proof.T2.getX().toString(), proof.T2.getY().toString());
// console.log((proof.tauX.toString()));
// console.log((proof.tHat.toString()));
// console.log((proof.mu.toString()));
// console.log(proof.innerProductProof.a.toString());
// console.log(proof.innerProductProof.b.toString());
// console.log(proof.innerProductProof.p.getX().toString(), proof.innerProductProof.p.getY().toString());
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
// // // proof.IsSafe()
// let bytes = proof.bytes();
// let bstr = "{";
// for (let b in bytes) {
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