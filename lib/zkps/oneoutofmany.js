const bn = require('bn.js');
const { P256 } = require('../ec');
const { base64Decode, convertIntToBinary, randScalar, addPaddingBigInt } = require('../privacy_utils');
const { generateChallenge, } = require('./utils');
const { PedCom } = require('../pedersen');
const { Poly } = require('../polynomials');
const { SK, BIG_INT_SIZE, COMPRESS_POINT_SIZE } = require('../constants');
const { CM_RING_SIZE, CM_RING_SIZE_EXP, ONE_OF_MANY_PROOF_SIZE } = require('./constants');


class OneOutOfManyStatement {
  constructor() {
    this.commitments = [];
  }

  set(commitments) {
    this.commitments = commitments
  }
}


class OneOutOfManyWitness {
  constructor() {
    this.rand = new bn(0);
    this.indexIsZero = 0;
    this.stmt = new OneOutOfManyStatement();
  }

  set(commitments, rand, indexIsZero) {
    this.rand = rand;
    this.indexIsZero = indexIsZero;
    this.stmt.set(commitments);
  }

  async prove() {
    let commitmentBytes = new Array(this.stmt.commitments.length)
    let commitmentStrs = new Array(this.stmt.commitments.length)
    for (let i = 0; i < this.stmt.commitments.length; i++) {
      commitmentBytes[i] = this.stmt.commitments[i].compress();
      commitmentStrs[i] = new bn(commitmentBytes[i]);
      // console.log("commitmentBytes ", i, ": ", commitmentBytes[i]);
      // console.log("commitmentStrs ", i, ": ", commitmentStrs[i]);
    }

    let tmpObject = {
      "commitments": commitmentStrs,
      "rand": [this.rand.toString()],
      "indexiszero" : [this.indexIsZero.toString()]
    }

    if (typeof oneOutOfManyProve  === "function"){
      console.log("HHH Start one of many proving with wasm........... ");
      console.log("oneOutOfManyProve: ", oneOutOfManyProve);
      console.time("one of many prove time wasm: ");
  
      let base64EncodedProof = await oneOutOfManyProve(JSON.stringify(tmpObject));
      let proofBytes = base64Decode(base64EncodedProof);
      console.log("proofBytes: ", proofBytes.join(", "));
      let proof = new (OneOutOfManyProof);
      proof.setBytes(proofBytes);
  
      console.timeEnd("one of many prove time wasm: ");
      return {
        proof: proof,
        err : null
      };
    } 


    console.time("one of many prove time without wasm: ");
    // Check the number of Commitment list's elements
    let N = this.stmt.commitments.length;
    if (N !== CM_RING_SIZE) {
      return {
        proof: new OneOutOfManyProof(),
        err: new Error("the number of Commitment list's elements must be equal to CM_RING_SIZE")
      }
    }

    let n = CM_RING_SIZE_EXP;

    // Check indexIsZero
    if (this.indexIsZero > N) {
      return {
        proof: new OneOutOfManyProof(),
        err: new Error("Index is zero must be Index in list of commitments")
      }
    }

    // represent indexIsZero in binary
    let indexIsZeroBinary = convertIntToBinary(this.indexIsZero, n);

    // randomness array
    let r = new Array(n); // big int array
    let a = new Array(n); // big int array
    let s = new Array(n); // big int array
    let t = new Array(n); // big int array
    let u = new Array(n); // big int array

    let cl = new Array(n); // elliptic point array
    let ca = new Array(n); // elliptic point array
    let cb = new Array(n); // elliptic point array
    let cd = new Array(n); // elliptic point array

    for (let j = 0; j < n; j++) {
      // Generate random numbers
      r[j] = randScalar();
      a[j] = randScalar();
      s[j] = randScalar();
      t[j] = randScalar();
      u[j] = randScalar();

      // convert indexIsZeroBinary[j] to big.Int
      let indexInt = new bn(indexIsZeroBinary[j]);

      // Calculate cl, ca, cb, cd
      // cl = Com(l, r)
      cl[j] = PedCom.commitAtIndex(indexInt, r[j], SK);

      // ca = Com(a, s)
      ca[j] = PedCom.commitAtIndex(a[j], s[j], SK);

      // cb = Com(la, t)
      let la = indexInt.mul(a[j]);
      cb[j] = PedCom.commitAtIndex(la, t[j], SK);

      // console.log('a: ', j, ': ', a[j].toArray().join(', '));
      // console.log('u: ', j, ': ', u[j].toArray().join(', '));
    }

    // console.log();

    // Calculate: cd_k = ci^pi,k
    for (let k = 0; k < n; k++) {
      // Calculate pi,k which is coefficient of x^k in polynomial pi(x)
      cd[k] = PedCom.commitAtIndex(new bn(0), u[k], SK);

      for (let i = 0; i < N; i++) {
        let iBinary = convertIntToBinary(i, n);
        let pik = GetCoefficient(iBinary, k, n, a, indexIsZeroBinary);
        cd[k] = cd[k].add(this.stmt.commitments[i].mul(pik));
      }
    }

    // Calculate challenge x
    let x = new bn(0);

    for (let j = 0; j < n; j++) {
      x = generateChallenge([x.toArray('be', BIG_INT_SIZE), cl[j].compress(), ca[j].compress(), cb[j].compress(), cd[j].compress()]);
    }

    // console.log("Challenge x: ", x.toArray('be', BIG_INT_SIZE));

    // Calculate za, zb zd
    let za = new Array(n); // big int array
    let zb = new Array(n); // big int array
    let f = new Array(n); // big int array

    for (let j = 0; j < n; j++) {
      // f = lx + a
      let indexInt = new bn(indexIsZeroBinary[j]);
      f[j] = indexInt.mul(x);
      f[j] = f[j].add(a[j]);
      f[j] = f[j].umod(P256.n);

      // za = s + rx
      za[j] = r[j].mul(x);
      za[j] = za[j].add(s[j]);
      za[j] = za[j].umod(P256.n);

      // zb = r(x - f) + t
      zb[j] = x.sub(f[j]);
      zb[j] = zb[j].mul(r[j]);
      zb[j] = zb[j].add(t[j]);
      zb[j] = zb[j].umod(P256.n);
    }

    // zd = rand * x^n - sum_{k=0}^{n-1} u[k] * x^k
    let zd = x.pow(new bn(n));
    zd = zd.mul(this.rand);

    // let uxInt = new BigInt(0);
    let sumInt = new bn(0);
    for (let k = 0; k < n; k++) {
      let uxInt = x.pow(new bn(k));
      uxInt = uxInt.mul(u[k]);
      sumInt = sumInt.add(uxInt);
      // sumInt = sumInt.umod(P256.n);
    }

    zd = zd.sub(sumInt);
    zd = zd.umod(P256.n);

    let proof = new OneOutOfManyProof();
    proof.set(this.stmt.commitments, cl, ca, cb, cd, f, za, zb, zd);

    console.timeEnd("one of many prove time without wasm: ");

    return {
      proof: proof,
      err: null
    }
  }
}

class OneOutOfManyProof {
  constructor() {
    this.cl = []; // []EllipticPoint
    this.ca = []; // []EllipticPoint
    this.cb = []; // []EllipticPoint
    this.cd = []; // []EllipticPoint
    this.f = []; // [] BigInt
    this.za = []; // [] BigInt
    this.zb = []; // [] BigInt
    this.zd = new bn(0);
    this.stmt = new OneOutOfManyStatement();
  }

  isNull() {
    if (this.cl.length === 0) {
      return true;
    }
    if (this.ca.length === 0) {
      return true;
    }
    if (this.cb.length === 0) {
      return true;
    }
    if (this.cd.length === 0) {
      return true;
    }
    if (this.f.length === 0) {
      return true;
    }
    if (this.za.length === 0) {
      return true;
    }
    if (this.zb.length === 0) {
      return true;
    }
    if (this.zd.eq(0)) {
      return true;
    }
    return false;
  }

  set(commitments, cl, ca, cb, cd, f, za, zb, zd) {
    this.stmt.commitments = commitments;
    this.cl = cl;
    this.ca = ca;
    this.cb = cb;
    this.cd = cd;
    this.f = f;
    this.za = za;
    this.zb = zb;
    this.zd = zd;
    return this;
  }

  toBytes() {
    // if proof is null, return an empty array
    if (this.isNull()) {
      return [];
    }

    let bytes = new Uint8Array(ONE_OF_MANY_PROOF_SIZE);
    let offset = 0;

    // N = 2^n
    let N = CM_RING_SIZE;
    let n = CM_RING_SIZE_EXP;

    // convert array cl to bytes array
    for (let i = 0; i < n; i++) {
      bytes.set(this.cl[i].compress(), offset);
      offset += COMPRESS_POINT_SIZE;
    }
    // convert array ca to bytes array
    for (let i = 0; i < n; i++) {
      let tmp = this.ca[i].compress();
      bytes.set(tmp, offset);
      offset += COMPRESS_POINT_SIZE;
    }

    // convert array cb to bytes array
    for (let i = 0; i < n; i++) {
      bytes.set(this.cb[i].compress(), offset);
      offset += COMPRESS_POINT_SIZE;
    }

    // convert array cd to bytes array
    for (let i = 0; i < n; i++) {
      bytes.set(this.cd[i].compress(), offset);
      offset += COMPRESS_POINT_SIZE;
    }

    // convert array f to bytes array
    for (let i = 0; i < n; i++) {
      bytes.set(this.f[i].toArray('be', BIG_INT_SIZE), offset);
      offset += BIG_INT_SIZE;
    }

    // convert array za to bytes array
    for (let i = 0; i < n; i++) {
      bytes.set(this.za[i].toArray('be', BIG_INT_SIZE), offset);
      offset += BIG_INT_SIZE;
    }

    // convert array zb to bytes array
    for (let i = 0; i < n; i++) {
      bytes.set(this.zb[i].toArray('be', BIG_INT_SIZE), offset);
      offset += BIG_INT_SIZE;
    }

    bytes.set(this.zd.toArray('be', BIG_INT_SIZE), offset);
    return bytes;
  }

  setBytes(bytes) {
    if (bytes.length === 0) {
      return null;
    }
    let n = CM_RING_SIZE_EXP;

    let offset = 0;
    this.cl = new Array(n);
    for (let i = 0; i < n; i++) {
      let tmp = bytes.slice(offset, offset + COMPRESS_POINT_SIZE);
      // console.log("HHHH tmp: ", tmp);
      this.cl[i] = P256.decompress(tmp);
      offset = offset + COMPRESS_POINT_SIZE;
    }
    // console.log("this.cl, ", this.cl);

    this.ca = new Array(n);
    for (let i = 0; i < n; i++) {
      let tmp = bytes.slice(offset, offset + COMPRESS_POINT_SIZE);
      // console.log("HHHH tmp 2: ", tmp);
      this.ca[i] = P256.decompress(bytes.slice(offset, offset + COMPRESS_POINT_SIZE));
      offset = offset + COMPRESS_POINT_SIZE;
    }
    // console.log("this.ca, ", this.ca);

    this.cb = new Array(n);
    for (let i = 0; i < n; i++) {
      let tmp = bytes.slice(offset, offset + COMPRESS_POINT_SIZE);
      // console.log("HHHH tmp 3: ", tmp);
      this.cb[i] = P256.decompress(bytes.slice(offset, offset + COMPRESS_POINT_SIZE));
      offset = offset + COMPRESS_POINT_SIZE;
    }
    // console.log("this.cb, ", this.cb);

    this.cd = new Array(n);
    for (let i = 0; i < n; i++) {
      let tmp = bytes.slice(offset, offset + COMPRESS_POINT_SIZE);
      // console.log("HHHH tmp 4: ", tmp);
      this.cd[i] = P256.decompress(bytes.slice(offset, offset + COMPRESS_POINT_SIZE));
      offset = offset + COMPRESS_POINT_SIZE;
    }
    // console.log("this.cd, ", this.cd);

    this.f = new Array(n);
    for (let i = 0; i < n; i++) {
      this.f[i] = new bn(bytes.slice(offset, offset + BIG_INT_SIZE));
      offset = offset + BIG_INT_SIZE;
    }
    // console.log("this.f, ", this.f);

    this.za = new Array(n);
    for (let i = 0; i < n; i++) {
      this.za[i] = new bn(bytes.slice(offset, offset + BIG_INT_SIZE));
      offset = offset + BIG_INT_SIZE;
    }
    // console.log("this.za, ", this.za);

    this.zb = new Array(n);
    for (let i = 0; i < n; i++) {
      this.zb[i] = new bn(bytes.slice(offset, offset + BIG_INT_SIZE));
      offset = offset + BIG_INT_SIZE;
    }
    // console.log("this.zb, ", this.zb);

    this.zd = new bn(bytes.slice(offset, offset + BIG_INT_SIZE));
    // console.log("this.zd, ", this.zd);
  }

  verify() {
    let N = this.stmt.commitments.length;

    // the number of Commitment list's elements must be equal to CMRingSize
    if (N !== CM_RING_SIZE) {
      return false
    }
    let n = CM_RING_SIZE_EXP;

    //Calculate challenge x
    let x = new bn(0);
    for (let j = 0; j < n; j++) {
      x = generateChallenge([addPaddingBigInt(x, BIG_INT_SIZE), this.cl[j].compress(), this.ca[j].compress(), this.cb[j].compress(), this.cd[j].compress()])
    }

    for (let i = 0; i < n; i++) {
      //Check cl^x * ca = Com(f, za)
      let leftPoint1 = this.cl[i].mul(x).add(this.ca[i]);
      let rightPoint1 = PedCom.commitAtIndex(this.f[i], this.za[i], SK);

      if (!leftPoint1.eq(rightPoint1)) {
        return false;
      }

      //Check cl^(x-f) * cb = Com(0, zb)s
      let xSubF = x.sub(this.f[i]);
      xSubF = xSubF.umod(P256.n);

      let leftPoint2 = this.cl[i].mul(xSubF).add(this.cb[i]);
      let rightPoint2 = PedCom.commitAtIndex(new bn(0), this.zb[i], SK);

      if (!leftPoint2.eq(rightPoint2)) {
        return false
      }
    }

    let leftPoint3 = P256.curve.point(0, 0);
    let leftPoint32 = P256.curve.point(0, 0);

    for (let i = 0; i < N; i++) {
      let iBinary = convertIntToBinary(i, n);

      let exp = new bn(1);
      let fji = new bn(0);

      for (let j = 0; j < n; j++) {
        if (iBinary[j] === 1) {
          fji = this.f[j];
        } else {
          fji = x.sub(this.f[j]);
          fji = fji.umod(P256.n);
        }

        exp = exp.mul(fji);
        exp = exp.umod(P256.n);
      }
      if (i === 0) {
        leftPoint3 = this.stmt.commitments[i].mul(exp);
      } else {
        leftPoint3 = leftPoint3.add(this.stmt.commitments[i].mul(exp))
      }
    }

    for (let k = 0; k < n; k++) {
      let xk = x.pow(new bn(k));
      xk = P256.n.sub(xk);
      xk = xk.umod(P256.n);

      if (k === 0) {
        leftPoint32 = this.cd[k].mul(xk);
      } else {
        leftPoint32 = leftPoint32.add(this.cd[k].mul(xk));
      }
    }

    leftPoint3 = leftPoint3.add(leftPoint32);

    let rightPoint3 = PedCom.commitAtIndex(new bn(0), this.zd, SK);

    return leftPoint3.eq(rightPoint3);
  }
}

// Get coefficient of x^k in the polynomial p_i(x)
function GetCoefficient(iBinary, k, n, a, l) {
  let res = new Poly([new bn(1)]);
  let fji = new Poly([]);

  for (let j = n - 1; j >= 0; j--) {
    let fj = new Poly([a[j], new bn(l[j])]);
    if (iBinary[j] === 0) {
      fji = new Poly([new bn(0), new bn(1)]).sub(fj, P256.n);
    } else {
      fji = fj;
    }
    res = res.mul(fji, P256.n);
  }

  if (res.getDegree() < k) {
    return new bn(0);
  }

  return res.Coeffs[k];
}

module.exports = {
  OneOutOfManyWitness,
  OneOutOfManyProof
};