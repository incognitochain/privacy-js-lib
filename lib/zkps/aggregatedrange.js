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
    this.innerProductProof = new aggUtils.InnerProductProof()
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
    let vector2powN = aggUtils.powerVector(numberTwo, n);
    // recalculate challenge y, z
    let y = params.generateChallengeForAggRange(aggParam, [this.A.compress(), this.S.compress()]);
    let z = params.generateChallengeForAggRange(aggParam, [this.A.compress(), this.S.compress(), y.toArray("be")]);
    let zSquare = z.mul(z);
    zSquare = zSquare.umod(p256.n);

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
    //  = vectorPowOfY[vectorPowOfY.length - 1].mul(y).sub(new BigInt(-1));
    // innerProduct1 = innerProduct1.div(y.sub(new BigInt(-1)));
    let innerProduct1 = new BigInt("0");
    for (let i = 0; i < vectorPowOfY.length; i++) {
      innerProduct1 = innerProduct1.add(vectorPowOfY[i])
    }
    // innerProduct1 = <1^(n*m), y^(n*m)>
    innerProduct1 = innerProduct1.umod(p256.n);
    deltaYZ = deltaYZ.mul(innerProduct1);

    // innerProduct2 = <1^n, 2^n>
    let innerProduct2 = vector2powN[vector2powN.length - 1].mul(numberTwo);
    innerProduct2 = innerProduct2.sub(new BigInt(1));
    innerProduct2 = innerProduct2.umod(p256.n);

    let sum = new BigInt("0");
    let zTmp = zSquare;
    for (let j = 0; j < numValuePad; j++) {
      zTmp = zTmp.mul(z);
      zTmp = zTmp.umod(p256.n);
      sum = sum.add(zTmp);
    }

    sum = sum.mul(innerProduct2);
    // console.log(deltaYZ.toString())

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
    let innerProductWit = new aggUtils.InnerProductWitness();
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
let wit = new AggregatedRangeWitness();
wit.set(values, rands);
let proof = wit.prove();

// console.log(proof.toBytes());
// let proof1 = new AggregatedRangeProof();
// let proofBytes =
//     [2,2,154,221,125,50,254,40,34,153,146,169,156,38,74,104,199,222,70,48,69,137,9,78,239,186,166,174,177,137,178,55,182,139,2,68,252,195,106,202,245,28,19,231,26,238,20,13,15,103,9,119,12,11,191,162,112,155,21,70,146,235,58,146,120,53,42,2,190,102,157,255,44,82,231,224,255,29,35,46,106,107,48,171,212,249,212,211,86,206,0,255,126,253,26,40,235,90,142,95,2,220,234,86,133,205,90,108,249,249,159,87,101,45,210,58,184,231,19,194,63,82,37,224,225,109,115,116,117,65,81,229,81,3,210,184,182,24,233,145,203,33,185,1,109,61,204,220,170,247,23,97,169,119,113,43,188,64,123,25,78,251,88,189,11,157,3,212,14,66,71,214,75,93,205,173,105,118,233,228,136,68,234,231,24,255,175,87,142,85,105,180,20,189,34,147,252,219,156,180,65,178,52,166,174,211,60,209,83,171,219,97,252,123,102,199,221,142,71,225,203,236,236,245,68,30,222,251,8,3,22,252,128,72,145,216,169,140,156,241,209,226,113,206,162,137,217,103,149,156,255,85,252,142,173,7,186,20,171,184,219,251,119,179,116,150,59,170,64,200,7,52,222,135,62,0,167,179,163,246,179,253,167,64,126,220,102,12,121,242,3,224,130,108,62,7,3,125,10,191,114,110,109,185,158,89,165,114,155,152,9,63,33,133,207,89,73,214,64,20,1,14,29,107,112,202,253,253,170,3,221,134,140,48,128,17,50,106,127,42,120,219,28,255,8,148,121,255,87,247,121,61,216,159,91,207,222,97,13,115,47,207,2,208,235,199,59,116,57,116,151,241,241,189,244,203,142,191,173,78,3,32,226,90,136,254,77,89,185,241,133,99,225,23,188,3,5,139,210,6,139,49,31,178,99,59,150,115,151,199,142,68,222,248,144,230,131,82,131,165,125,109,252,12,154,190,33,141,3,24,157,189,113,177,92,79,182,45,201,203,13,87,157,190,57,102,160,187,230,147,78,91,98,139,243,139,198,254,209,203,108,3,116,214,234,147,85,89,207,83,152,120,5,67,170,138,68,179,50,81,233,244,137,173,2,177,202,0,10,236,144,141,117,58,2,60,202,16,39,77,123,113,37,174,96,75,47,228,177,114,44,98,239,192,175,242,26,175,120,42,67,46,143,106,191,8,98,3,200,255,123,88,10,207,206,12,216,251,171,239,123,206,214,211,12,228,142,240,88,154,218,158,21,83,85,83,48,198,21,49,2,241,237,98,86,249,154,246,70,107,66,87,88,158,94,31,9,95,4,204,224,208,135,161,48,132,152,93,161,181,238,166,152,3,105,5,26,91,180,238,179,39,28,56,146,107,205,245,113,128,94,55,27,225,93,158,1,93,14,141,106,61,177,180,243,40,2,241,33,252,47,183,50,176,95,227,84,137,71,61,173,201,157,138,172,250,88,80,105,198,43,148,106,32,175,17,192,240,223,3,245,208,44,72,31,163,18,150,168,12,202,187,243,58,122,172,242,196,173,118,170,123,202,143,113,16,11,28,231,81,223,34,3,114,246,158,72,57,12,69,195,202,247,127,96,35,2,116,17,234,142,102,142,112,120,222,202,172,29,71,197,224,187,165,64,2,128,241,127,228,31,236,154,108,1,224,111,63,152,89,100,103,182,190,121,59,80,178,242,17,131,56,144,178,162,104,173,24,115,154,215,3,167,102,128,90,56,42,235,173,149,247,4,14,247,215,157,50,69,163,82,109,113,161,96,231,250,177,5,203,187,94,35,241,35,74,255,122,253,18,47,138,33,84,230,94,90,223,238,181,12,101,211,122,71,132,99,228,147,225,198,126,3,86,227,51,189,239,113,11,119,126,84,123,75,31,173,170,147,17,253,118,137,28,145,237,201,148,107,14,135,229,23,228,251]// //
// proof1.setBytes(proofBytes);
// //
console.log(proof.verify());
// console.log(proof.A.getX().toString(), proof.A.getY().toString());
// console.log(proof.S.getX().toString(), proof.S.getY().toString());
// console.log(proof.T1.getX().toString(), proof.T1.getY().toString());
// console.log(proof.T2.getX().toString(), proof.T2.getY().toString());
// console.log((proof.tauX.toString()));
// console.log((proof.tHat.toString()));
// console.log((proof.mu.toString()));
// console.log(proof.InnerProductProof.a.toString());
// console.log(proof.InnerProductProof.b.toString());
// console.log(proof.InnerProductProof.p.getX().toString(), proof.InnerProductProof.p.getY().toString());
// console.log("------------------")
// for (let i=0;i<proof.InnerProductProof.l.length;i++){
//     console.log(proof.InnerProductProof.l[i].getX().toString(),proof.InnerProductProof.l[i].getY().toString())
//
// }
// console.log("------------------")
// for (let i=0;i<proof.InnerProductProof.l.length;i++){
//     console.log(proof.InnerProductProof.r[i].getX().toString(),proof.InnerProductProof.r[i].getY().toString())
//
// }
// console.log(proof.InnerProductProof.a.toString());
// console.log(proof.InnerProductProof.b.toString());
// console.log(proof.InnerProductProof.p.getX().toString(),proof.InnerProductProof.p.getY().toString())

// // proof.Print();
// // // proof.IsSafe()
// let bytes = proof.toBytes();
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