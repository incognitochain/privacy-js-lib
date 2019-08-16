const bn = require('bn.js');
const { P256 }  = require("../ec");
const { base64Decode, convertIntToBinary, randScalar } = require('../privacy_utils');
const { InnerProductWitness, InnerProductProof,  pad, powerVector, vectorMulScalar, vectorAdd, vectorAddScalar, hadamardProduct, innerProduct  } = require("./aggregatedrange_utils");
const { BulletproofParams, generateChallengeForAggRange, EncodeVectors } = require("./aggregaterangeparams");
const { PedCom } = require("../pedersen");
const { MAX_EXP } = require('./constants');
const { BIG_INT_SIZE, COMPRESS_POINT_SIZE, VALUE, RAND } = require('../constants');

async function sleep(sleepTime) {
  return new Promise(resolve => setTimeout(resolve, sleepTime));
}

let isWASMRunned = false;
try{
  if (!isWASMRunned){
    require('isomorphic-fetch');
    require("../../wasm_exec")
    var fs = require('fs');
    const go = new Go();
    let inst;
    if (fs.readFileSync) {
      let data = fs.readFileSync("./privacy.wasm")
      WebAssembly.instantiate(data, go.importObject).then((result) => {
        inst = result.instance;
        go.run(inst);
        isWASMRunned = true;
      });
    } else {
      if (!WebAssembly.instantiateStreaming) { // polyfill
        WebAssembly.instantiateStreaming = async (resp, importObject) => {
          const source = await (await resp).arrayBuffer();
          console.log("WebAssembly source", source);
          return await WebAssembly.instantiate(source, importObject);
        };
      }
      WebAssembly.instantiateStreaming(fetch("./privacy.wasm"), go.importObject).then(async (result) => {
        inst = result.instance;
        go.run(inst);
        isWASMRunned = true;
      });
    }
  }
} catch(e){
  console.log("Running on mobile app: ", e);
}

class AggregatedRangeProof {
  constructor() {
    this.cmsValue = [];
    this.A = P256.curve.point(0, 0);
    this.S = P256.curve.point(0, 0);
    this.T1 = P256.curve.point(0, 0);
    this.T2 = P256.curve.point(0, 0);
    this.tauX = new bn("0");
    this.tHat = new bn("0");
    this.mu = new bn("0");
    this.innerProductProof = new InnerProductProof()
  }

  toBytes() {
    let l = 1 + COMPRESS_POINT_SIZE * this.cmsValue.length;
    let innerProBytes = this.innerProductProof.bytes();
    l = l + COMPRESS_POINT_SIZE * 4 + BIG_INT_SIZE * 3 + innerProBytes.length;
    let bytes = new Uint8Array(l);
    let offset = 1;
    bytes.set([this.cmsValue.length], 0);
    for (let i = 0; i < this.cmsValue.length; i++) {
      bytes.set(this.cmsValue[i].compress(), offset);
      offset = offset + COMPRESS_POINT_SIZE;
    }
    bytes.set(this.A.compress(), offset);
    offset += COMPRESS_POINT_SIZE;
    bytes.set(this.S.compress(), offset);
    offset += COMPRESS_POINT_SIZE;
    bytes.set(this.T1.compress(), offset);
    offset += COMPRESS_POINT_SIZE;
    bytes.set(this.T2.compress(), offset);
    offset += COMPRESS_POINT_SIZE;
    bytes.set(this.tauX.toArray("be", BIG_INT_SIZE), offset);
    offset += BIG_INT_SIZE;
    bytes.set(this.tHat.toArray("be", BIG_INT_SIZE), offset);
    offset += BIG_INT_SIZE;
    bytes.set(this.mu.toArray("be", BIG_INT_SIZE), offset);
    offset += BIG_INT_SIZE;
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
      this.cmsValue[i] = P256.decompress(bytes.slice(offset, offset + COMPRESS_POINT_SIZE));
      offset = offset + COMPRESS_POINT_SIZE;
    }
    this.A = P256.decompress(bytes.slice(offset, offset + COMPRESS_POINT_SIZE));
    offset = offset + COMPRESS_POINT_SIZE;

    this.S = P256.decompress(bytes.slice(offset, offset + COMPRESS_POINT_SIZE));
    offset = offset + COMPRESS_POINT_SIZE;

    this.T1 = P256.decompress(bytes.slice(offset, offset + COMPRESS_POINT_SIZE));
    offset = offset + COMPRESS_POINT_SIZE;

    this.T2 = P256.decompress(bytes.slice(offset, offset + COMPRESS_POINT_SIZE));
    offset = offset + COMPRESS_POINT_SIZE;

    this.tauX = new bn(bytes.slice(offset, offset + BIG_INT_SIZE), 16, "be");
    offset = offset + BIG_INT_SIZE;

    this.tHat = new bn(bytes.slice(offset, offset + BIG_INT_SIZE), 16, "be");
    offset = offset + BIG_INT_SIZE;

    this.mu = new bn(bytes.slice(offset, offset + BIG_INT_SIZE), 16, "be");
    offset = offset + BIG_INT_SIZE;

    this.innerProductProof.setBytes(bytes.slice(offset));
  }

  verify() {
    let numValue = this.cmsValue.length;
    let numValuePad = pad(numValue);
    for (let i = numValue; i < numValuePad; i++) {
      this.cmsValue.push(P256.curve.point(0, 0));
    }
    let aggParam = new BulletproofParams(numValuePad);
    let n = MAX_EXP;

    let numberTwo = new bn("2");
    let vector2powN = powerVector(numberTwo, n);
    // recalculate challenge y, z
    let y = generateChallengeForAggRange(aggParam, [this.A.compress(), this.S.compress()]);
    let z = generateChallengeForAggRange(aggParam, [this.A.compress(), this.S.compress(), y.toArray("be")]);
    let zSquare = z.mul(z);
    zSquare = zSquare.umod(P256.n);

    // challenge x = hash(G || H || A || S || T1 || T2)
    let x = generateChallengeForAggRange(aggParam, [this.A.compress(), this.S.compress(), this.T1.compress(), this.T2.compress()]);
    let xSquare = x.mul(x);
    xSquare = xSquare.umod(P256.n);

    let vectorPowOfY = powerVector(y, n * numValuePad);

    let HPrime = new Array(n * numValuePad);
    for (let i = 0; i < n * numValuePad; i++) {
      let yPowMinusOne = y.pow(new bn(i));
      yPowMinusOne = yPowMinusOne.invm(P256.n);
      HPrime[i] = aggParam.H[i].mul(yPowMinusOne);
    }
    // g^tHat * h^tauX = V^(z^2) * g^delta(y,z) * T1^x * T2^(x^2)
    let deltaYZ = z.sub(zSquare);
    //  = vectorPowOfY[vectorPowOfY.length - 1].mul(y).sub(new BigInt(-1));
    // innerProduct1 = innerProduct1.div(y.sub(new BigInt(-1)));
    let innerProduct1 = new bn("0");
    for (let i = 0; i < vectorPowOfY.length; i++) {
      innerProduct1 = innerProduct1.add(vectorPowOfY[i])
    }
    // innerProduct1 = <1^(n*m), y^(n*m)>
    innerProduct1 = innerProduct1.umod(P256.n);
    deltaYZ = deltaYZ.mul(innerProduct1);

    // innerProduct2 = <1^n, 2^n>
    let innerProduct2 = vector2powN[vector2powN.length - 1].mul(numberTwo);
    innerProduct2 = innerProduct2.sub(new bn(1));
    innerProduct2 = innerProduct2.umod(P256.n);

    let sum = new bn("0");
    let zTmp = zSquare;
    for (let j = 0; j < numValuePad; j++) {
      zTmp = zTmp.mul(z);
      zTmp = zTmp.umod(P256.n);
      sum = sum.add(zTmp);
    }

    sum = sum.mul(innerProduct2);
    // console.log(deltaYZ.toString())

    deltaYZ = deltaYZ.sub(sum);

    deltaYZ = deltaYZ.umod(P256.n);

    let left = PedCom.commitAtIndex(this.tHat, this.tauX, VALUE);
    let right = PedCom.G[VALUE].mul(deltaYZ).add(this.T1.mul(x)).add(this.T2.mul(xSquare));
    let expVector = vectorMulScalar(powerVector(z, numValuePad), zSquare);
    for (let i = 0; i < this.cmsValue.length; i++) {
      right = right.add(this.cmsValue[i].mul(expVector[i]))
    }
    if (left.getX().cmp(right.getX()) !== 0 && left.getY().cmp(right.getY()) !== 0) {
      console.log("False 1");
      return false;
    }

    console.log("False 2");
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

  async prove() {
    let numValues = this.values.length;
    let valueStrs = new Array(numValues)
    let randStrs = new Array(numValues)

    for (let i = 0; i < numValues; i++) {
      valueStrs[i] = this.values[i].toString();
      randStrs[i] = this.rands[i].toString();
    }

    let tmpObject = {
      "values": valueStrs,
      "rands": randStrs
    }

    await sleep(1000);
    if (typeof aggregatedRangeProve  === "function"){
      console.log("Start aggregated range proving........... ");
      console.log("aggregatedRangeProve: ", aggregatedRangeProve);
      console.time("aggregated range prove time wasm: ");
  
      let base64EncodedProof = await aggregatedRangeProve(JSON.stringify(tmpObject));
  
      // console.log("proof base64 encode get from WASM: ", proof);
      let proofBytes = base64Decode(base64EncodedProof);
      console.log("proofBytes: ", proofBytes.join(", "));
      let proof = new (AggregatedRangeProof);
      proof.setBytes(proofBytes);
  
      console.timeEnd("aggregated range prove time wasm: ");
      return proof;
    } 

    // Aggregated range prove without WASM
    console.time("bullet proof init data:");
    let proof = new AggregatedRangeProof();
    let numValue = this.values.length;
    let numValuePad = pad(numValue);
    let values = new Array(numValuePad);
    let rands = new Array(numValuePad);
    for (let i = 0; i < numValue; i++) {
      values[i] = this.values[i];
      rands[i] = this.rands[i];
    }
    for (let i = numValue; i < numValuePad; i++) {
      values[i] = new bn("0");
      rands[i] = new bn("0");
    }
    console.timeEnd("bullet proof init data:");
  
    debugger;

    console.time("init BulletproofParams");
    let AggParam = new BulletproofParams(numValuePad);
    proof.cmsValue = new Array(numValue);
    for (let i = 0; i < numValue; i++) {
      proof.cmsValue[i] = PedCom.commitAtIndex(values[i], rands[i], VALUE);
    }
    console.timeEnd("init BulletproofParams");

    console.time("vectorMinusOne:");
    let n = MAX_EXP;
    let aL = new Array(numValuePad);
    for (let i = 0; i < values.length; i++) {
      let tmp = convertIntToBinary(values[i], n);
      console.log("Values[i] in binary: ", tmp.join(""));
      for (let j = 0; j < n; j++) {
        aL[i * n + j] = new bn(tmp[j])
      }
    }

    let numberTwo = new bn("2");
    let vectorMinusOne = new Array(numValuePad * n);
    for (let i = 0; i < n * numValuePad; i++) {
      vectorMinusOne[i] = new bn("-1")
    }

    console.timeEnd("vectorMinusOne:");

    let vector2powN = powerVector(numberTwo, n);
    let aR = vectorAdd(aL, vectorMinusOne);

    console.time("alpha: ");
    let alpha = randScalar();
    let A = EncodeVectors(aL, aR, AggParam.G, AggParam.H);
    A = A.add(PedCom.G[RAND].mul(alpha));
    proof.A = A;
    console.timeEnd("alpha: ");

    console.time("sL, sR:");
    // Random blinding vectors sL, sR
    let sL = new Array(numValuePad * n);
    let sR = new Array(numValuePad * n);
    for (let i = 0; i < n * numValuePad; i++) {
      sL[i] = randScalar();
      sR[i] = randScalar();
    }
    console.timeEnd("sL, sR:");

    console.time("rho:");
    let rho = randScalar();
    let S = EncodeVectors(sL, sR, AggParam.G, AggParam.H);
    S = S.add(PedCom.G[RAND].mul(rho));
    proof.S = S;
    console.timeEnd("rho:");

    console.time("challenge y, z");
    // challenge y, z
    let y = generateChallengeForAggRange(AggParam, [A.compress(), S.compress()]);
    let z = generateChallengeForAggRange(AggParam, [A.compress(), S.compress(), y.toArray("be")]);
    let zNeg = z.neg();
    zNeg = zNeg.umod(P256.n);
    let zSquare = z.mul(z);
    zSquare = zSquare.umod(P256.n);
    let vectorPowOfY = powerVector(y, n * numValuePad);
    let l0 = vectorAddScalar(aL, zNeg);

    let l1 = sL;
    // r(X) = y^n hada (aR +z*1^n + sR*X) + z^2 * 2^n
    let hadaProduct = hadamardProduct(vectorPowOfY, vectorAddScalar(aR, z));


    let vectorSum = new Array(numValuePad * n);
    let zTmp = z;
    for (let j = 0; j < numValuePad; j++) {
      zTmp = zTmp.mul(z);
      zTmp = zTmp.umod(P256.n);
      for (let i = 0; i < n; i++) {
        vectorSum[j * n + i] = vector2powN[i].mul(zTmp);
        vectorSum[j * n + i] = vectorSum[j * n + i].umod(P256.n);
      }
    }

    let r0 = vectorAdd(hadaProduct, vectorSum);
    let r1 = hadamardProduct(vectorPowOfY, sR);
    //t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2
    let deltaYZ = z.sub(zSquare);
    console.timeEnd("challenge y, z");

    console.time("innerProduct");
    let innerProduct1 = vectorPowOfY[vectorPowOfY.length - 1].mul(y).sub(new bn(-1));
    // innerProduct1 = <1^(n*m), y^(n*m)>
    innerProduct1 = innerProduct1.umod(P256.n);
    deltaYZ = deltaYZ.mul(innerProduct1);

    // innerProduct2 = <1^n, 2^n>
    let innerProduct2 = vector2powN[vector2powN.length - 1].mul(numberTwo).sub(new bn(-1));
    innerProduct2 = innerProduct2.umod(P256.n);

    let sum = new bn("0");
    zTmp = zSquare;
    for (let j = 0; j < numValuePad; j++) {
      zTmp = zTmp.mul(z);
      zTmp = zTmp.umod(P256.n);
      sum = sum.add(zTmp);
    }
    sum = sum.mul(innerProduct2);
    deltaYZ = deltaYZ.sub(sum);
    deltaYZ = deltaYZ.umod(P256.n);

    // t1 = <l1, r0> + <l0, r1>
    let innerProduct3 = innerProduct(l1, r0);
    let innerProduct4 = innerProduct(l0, r1);
    let t1 = innerProduct3.add(innerProduct4);
    t1 = t1.umod(P256.n);
    let t2 = innerProduct(l1, r1);
    console.timeEnd("innerProduct");

    console.time("calculate param 1:");
    // commitment to t1, t2
    let tau1 = randScalar();
    let tau2 = randScalar();

    proof.T1 = PedCom.commitAtIndex(t1, tau1, VALUE);
    proof.T2 = PedCom.commitAtIndex(t2, tau2, VALUE);
    // challenge x = hash(G || H || A || S || T1 || T2)
    let x = generateChallengeForAggRange(AggParam, [proof.A.compress(), proof.S.compress(), proof.T1.compress(), proof.T2.compress()])
    let xSquare = x.mul(x);
    xSquare = xSquare.umod(P256.n);
    console.timeEnd("calculate param 1:");

    console.time("calculate param 2:");
    // lVector = aL - z*1^n + sL*x
    let lVector = vectorAdd(vectorAddScalar(aL, zNeg), vectorMulScalar(sL, x));
    // rVector = y^n hada (aR +z*1^n + sR*x) + z^2*2^n
    let tmpVector = vectorAdd(vectorAddScalar(aR, z), vectorMulScalar(sR, x));
    let rVector = hadamardProduct(vectorPowOfY, tmpVector);
    vectorSum = new Array(numValuePad * n);
    zTmp = z;
    for (let j = 0; j < numValuePad; j++) {
      zTmp = zTmp.mul(z);
      zTmp = zTmp.umod(P256.n);
      for (let i = 0; i < n; i++) {
        vectorSum[j * n + i] = vector2powN[i].mul(zTmp);
        vectorSum[j * n + i] = vectorSum[j * n + i].umod(P256.n);
      }
    }
    rVector = vectorAdd(rVector, vectorSum);
    // tHat = <lVector, rVector>
    proof.tHat = innerProduct(lVector, rVector);
    // blinding value for tHat: tauX = tau2*x^2 + tau1*x + z^2*rand
    proof.tauX = tau2.mul(xSquare);
    proof.tauX = proof.tauX.add(tau1.mul(x));
    zTmp = z;
    for (let j = 0; j < numValuePad; j++) {
      zTmp = zTmp.mul(z);
      zTmp = zTmp.umod(P256.n);
      proof.tauX = proof.tauX.add(zTmp.mul(rands[j]))
    }
    proof.tauX = proof.tauX.umod(P256.n);
    // alpha, rho blind A, S
    // mu = alpha + rho*x
    proof.mu = rho.mul(x);
    proof.mu = proof.mu.add(alpha);
    proof.mu = proof.mu.umod(P256.n);
    console.timeEnd("calculate param:");

    console.time("innerProductWit.prove:");
    // instead of sending left vector and right vector, we use inner sum argument to reduce proof size from 2*n to 2(log2(n)) + 2
    let innerProductWit = new InnerProductWitness();
    innerProductWit.a = lVector;
    innerProductWit.b = rVector;
    innerProductWit.p = EncodeVectors(lVector, rVector, AggParam.G, AggParam.H);
    innerProductWit.p = innerProductWit.p.add(AggParam.U.mul(proof.tHat));
    proof.innerProductProof = innerProductWit.prove(AggParam);
    console.timeEnd("innerProductWit.prove:");
    return proof
  }
}

module.exports = {
  AggregatedRangeProof,
  AggregatedRangeWitness
};
