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

  toBytes() {
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
    let innerProduct1 = vectorPowOfY[vectorPowOfY.length - 1].mul(y).sub(new BigInt(-1));
    // innerProduct1 = <1^(n*m), y^(n*m)>
    innerProduct1 = innerProduct1.umod(p256.n);
    deltaYZ = deltaYZ.mul(innerProduct1);

    // innerProduct2 = <1^n, 2^n>
    let innerProduct2 = vector2powN[vector2powN.length - 1].mul(numberTwo).sub(new BigInt(-1));
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
    console.time("AggregatedRangeWitness prove()")
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


    let innerProduct1 = vectorPowOfY[vectorPowOfY.length - 1].mul(y).sub(new BigInt(-1));
    // innerProduct1 = <1^(n*m), y^(n*m)>
    innerProduct1 = innerProduct1.umod(p256.n);
    deltaYZ = deltaYZ.mul(innerProduct1);

    // innerProduct2 = <1^n, 2^n>
    let innerProduct2 = vector2powN[vector2powN.length - 1].mul(numberTwo).sub(new BigInt(-1));
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

    console.timeEnd("AggregatedRangeWitness prove()")
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
// let wit = new AggregatedRangeWitness();
// wit.set(values, rands);
// let proof = wit.prove();
// console.log(proof.bytes());
// let proof1 = new AggregatedRangeProof();
// let proofBytes =
//     [3,2,27,164,42,147,128,15,216,180,97,213,149,34,5,64,212,243,131,235,130,79,240,72,196,35,213,228,141,224,226,156,119,101,2,27,164,42,147,128,15,216,180,97,213,149,34,5,64,212,243,131,235,130,79,240,72,196,35,213,228,141,224,226,156,119,101,2,27,164,42,147,128,15,216,180,97,213,149,34,5,64,212,243,131,235,130,79,240,72,196,35,213,228,141,224,226,156,119,101,2,72,103,104,19,43,162,158,87,129,61,83,83,186,82,208,253,155,19,7,5,243,55,173,2,247,4,154,90,182,67,48,242,3,124,238,152,37,90,95,90,92,25,158,155,183,61,157,100,20,60,57,176,81,181,82,172,29,143,203,134,86,115,113,252,12,2,140,12,222,41,19,74,190,154,76,114,29,202,243,216,245,52,46,160,8,17,85,97,195,114,116,95,240,166,213,142,254,59,2,46,220,181,78,84,138,232,255,199,58,52,123,176,77,46,32,158,74,75,201,125,72,74,226,43,208,100,61,46,241,165,195,56,126,225,17,1,170,89,34,250,200,149,43,44,106,228,42,85,15,153,158,248,126,49,250,240,212,196,38,148,70,191,188,129,110,177,145,6,224,176,132,204,141,229,100,151,247,121,140,109,197,171,159,129,192,97,107,245,112,81,53,23,5,60,128,195,0,160,40,22,4,48,71,222,198,75,80,159,203,171,168,61,90,37,242,251,52,46,198,239,86,108,227,218,154,35,185,8,2,5,232,186,148,22,115,1,44,70,238,7,228,93,119,227,65,16,137,93,163,66,77,235,57,65,179,4,24,231,25,95,196,3,245,246,16,56,127,112,147,37,150,63,247,65,62,65,4,94,54,108,61,206,40,10,231,158,38,182,52,52,116,218,49,121,3,15,103,47,37,157,62,164,43,155,161,47,249,189,164,31,11,148,31,26,123,197,121,189,209,119,181,3,107,233,189,142,148,3,253,157,108,104,215,38,231,101,147,252,183,147,170,77,96,176,172,191,193,54,185,174,73,216,122,83,202,171,14,3,181,240,2,217,205,232,27,193,137,117,6,140,80,69,123,151,246,175,150,64,192,127,240,246,35,159,29,238,174,122,91,67,81,252,235,3,82,206,123,12,246,143,166,37,253,171,71,148,153,228,52,225,202,21,200,71,107,43,189,148,22,58,93,31,140,187,243,38,2,56,117,106,242,121,109,38,179,186,108,63,192,238,178,60,21,137,212,49,88,197,56,46,192,109,13,56,191,143,77,162,23,3,59,68,173,229,252,38,141,72,75,124,163,124,226,78,229,87,102,125,24,80,233,9,120,109,203,49,222,147,169,110,202,10,3,24,23,95,188,234,75,86,33,170,21,221,120,165,165,213,184,37,234,255,188,36,38,172,125,179,132,61,77,168,55,74,76,2,160,185,139,52,225,102,51,11,199,242,142,100,163,115,171,60,159,228,154,28,161,147,227,200,90,88,45,85,202,215,252,67,3,52,247,184,84,89,17,104,161,201,70,37,102,88,126,216,10,197,115,99,24,73,220,80,220,103,234,62,41,95,57,20,97,3,243,31,110,42,156,134,93,26,155,209,255,22,103,206,51,86,228,204,7,242,172,152,202,10,236,17,6,146,219,49,198,3,2,156,192,223,134,98,167,229,217,71,239,238,163,172,192,64,49,82,43,115,159,221,21,220,223,198,39,202,64,13,9,48,202,2,2,120,221,176,86,110,169,133,54,13,99,164,22,230,61,74,87,146,182,198,89,155,27,84,182,155,184,51,76,232,253,145,3,58,234,47,230,183,53,99,31,138,57,53,137,34,12,41,187,134,106,209,13,108,152,246,240,157,27,60,142,10,124,145,131,2,211,24,215,21,146,161,144,173,44,239,105,16,127,72,99,38,164,123,14,167,223,30,172,58,159,134,194,193,127,61,247,242,74,224,151,161,187,239,14,194,30,229,243,231,230,42,229,222,235,168,236,89,0,104,163,174,3,92,169,193,215,209,186,82,244,50,29,80,75,108,239,105,144,163,246,104,152,185,63,227,64,135,223,78,83,149,243,55,18,251,179,112,137,163,254,104,2,173,149,33,72,14,111,177,75,87,95,173,89,37,240,225,48,55,97,137,13,187,244,176,18,109,58,218,77,199,26,210,44]
// //
// proof1.setBytes(proofBytes);
// //
// console.log(proof1.verify());
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