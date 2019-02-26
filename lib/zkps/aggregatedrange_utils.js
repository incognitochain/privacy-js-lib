let BigInt = require('bn.js');
let utils = require('../privacy_utils');
let constant = require('../constants');
let p256 = require('../ec').P256;
const spawn = require('threads').spawn;

let zeroPoint = p256.curve.point(0, 0);
let aggParams = require("./aggregaterangeparams");

class innerProductWitness {
  constructor() {
    this.a = [];
    this.b = [];
    this.p = zeroPoint
  }

  async prove(AggParam) {
    if (this.a.length !== this.b.length) {
      return null
    }
    let n = this.a.length;
    let a = new Array(n);
    let b = new Array(n);
    for (let i = 0; i < n; i++) {
      a[i] = this.a[i];
      b[i] = this.b[i];
    }
    let p = p256.curve.point(this.p.getX(), this.p.getY());
    let G = new Array(n);
    let H = new Array(n);
    for (let i = 0; i < n; i++) {
      G[i] = p256.curve.point(AggParam.G[i].getX(), AggParam.G[i].getY());
      H[i] = p256.curve.point(AggParam.H[i].getX(), AggParam.H[i].getY());
    }
    let proof = new innerProductProof();
    proof.l = [];
    proof.r = [];
    proof.p = this.p;
    console.time("While")
    while (n > 1) {
      let temp = n;
      console.time("While" + temp)
      let nPrime = n / 2;

      console.time("1.")
      let cL = innerProduct(a.slice(0, nPrime), b.slice(nPrime,));
      let cR = innerProduct(a.slice(nPrime,), b.slice(0, nPrime));
      console.timeEnd("1.")

      console.time("2.")
      console.time("2.1")
      let L = aggParams.EncodeVectors(a.slice(0, nPrime), b.slice(nPrime,), G.slice(nPrime,), H.slice(0, nPrime));
      L = L.add(AggParam.U.mul(cL));
      proof.l = proof.l.concat(L);
      console.timeEnd("2.1")
      console.time("2.2")
      let R = aggParams.EncodeVectors(a.slice(nPrime,), b.slice(0, nPrime), G.slice(0, nPrime), H.slice(nPrime,));
      R = R.add(AggParam.U.mul(cR));
      proof.r = proof.r.concat(R);
      console.timeEnd("2.2")
      console.timeEnd("2.")

      // calculate challenge x = hash(G || H || u || p ||  l || r)
      console.time("3.")
      let x = aggParams.generateChallengeForAggRange(AggParam, [p.compress(), L.compress(), R.compress()]);
      let xInverse = x.invm(p256.n);
      let GPrime = new Array(nPrime);
      let HPrime = new Array(nPrime);
      console.time("3.1")
      const thread = spawn(function (input) {
        return new Promise(resolve => {
          let p256 = require(input.__dirname + "/ec").P256
          let BigInt = require("bn.js")

          let Gi = input.data.Gi;
          let GnPrime = input.data.GnPrime;
          let Hi = input.data.Hi;
          let HnPrime = input.data.HnPrime;
          let xInverse = input.data.xInverse;
          let x = input.data.x;

          Object.setPrototypeOf(Gi, ArrayBuffer.prototype)
          let gi = new Uint8Array(Gi)
          gi = p256.decompress(gi);

          Object.setPrototypeOf(GnPrime, ArrayBuffer.prototype)
          let gnPrime = new Uint8Array(GnPrime)
          gnPrime = p256.decompress(gnPrime);

          Object.setPrototypeOf(Hi, ArrayBuffer.prototype)
          let hi = new Uint8Array(Hi)
          hi = p256.decompress(hi);

          Object.setPrototypeOf(HnPrime, ArrayBuffer.prototype)
          let hnPrime = new Uint8Array(HnPrime)
          hnPrime = p256.decompress(hnPrime);

          Object.setPrototypeOf(x, ArrayBuffer.prototype)
          x = new BigInt(x, 10)

          Object.setPrototypeOf(xInverse, ArrayBuffer.prototype)
          xInverse = new BigInt(xInverse, 10)

          GPrime = gi.mul(xInverse).add(gnPrime.mul(x))
          HPrime = hi.mul(xInverse).add(hnPrime.mul(x))

          let result = [GnPrime, HnPrime]
          resolve(result);
        })
      });
      const results = await Promise.all(Array.from({length: nPrime}).map((_, i) => {
        var path = require("path");
        return new Promise(function (resolve, _) {
          thread.send({
            __dirname: path.resolve("./lib/"),
            data: {
              Gi: [...G[i].compress()],
              GnPrime: [...G[i + nPrime].compress()],
              Hi: [...H[i].compress()],
              HnPrime: [...H[i + nPrime].compress()],
              xInverse: xInverse.toArray(),
              x: x.toArray()
            }
          }).on('message', function (response) {
            resolve(response);
          });
        })
      }))
      for (let i = 0; i < nPrime; i++) {
        GPrime[i] = p256.decompress(results[i][0])
        HPrime[i] = p256.decompress(results[i][1])
      }

      /*for (let i = 0; i < nPrime; i++) {
        GPrime[i] = G[i].mul(xInverse).add(G[i + nPrime].mul(x));
        HPrime[i] = H[i].mul(x).add(H[i + nPrime].mul(xInverse));
      }*/
      console.timeEnd("3.1")
      let xSquare = x.mul(x);
      let xSquareInverse = xSquare.invm(p256.n);
      let PPrime = L.mul(xSquare).add(p).add(R.mul(xSquareInverse));
      console.timeEnd("3.")

      // calculate aPrime, bPrime
      console.time("4.")
      let aPrime = new Array(nPrime);
      let bPrime = new Array(nPrime);
      console.time("4.1")
      for (let i = 0; i < nPrime; i++) {
        aPrime[i] = a[i].mul(x);
        aPrime[i] = aPrime[i].add(a[i + nPrime].mul(xInverse));
        aPrime[i] = aPrime[i].umod(p256.n);

        bPrime[i] = b[i].mul(xInverse);
        bPrime[i] = bPrime[i].add(b[i + nPrime].mul(x));
        bPrime[i] = bPrime[i].umod(p256.n);
      }
      console.timeEnd("4.1")

      a = aPrime;
      b = bPrime;
      p = p256.curve.point(PPrime.getX(), PPrime.getY());
      G = GPrime;
      H = HPrime;
      n = nPrime;
      console.timeEnd("4.")

      console.timeEnd("While" + temp)
    }
    console.timeEnd("While")

    proof.a = a[0];
    proof.b = b[0];

    return proof
  }
}

class innerProductProof {
  constructor() {
    this.l = [];
    this.r = [];
    this.a = new BigInt("0");
    this.b = new BigInt("0");
    this.p = p256.curve.point(0, 0);
  }

  bytes() {
    let l = 1 + constant.COMPRESS_POINT_SIZE * (this.l.length + this.r.length) + 2 * constant.BIG_INT_SIZE + constant.COMPRESS_POINT_SIZE;
    let bytes = new Uint8Array(l);
    let offset = 0;
    bytes.set([this.l.length], offset);
    offset++;
    for (let i = 0; i < this.l.length; i++) {
      bytes.set(this.l[i].compress(), offset);
      offset += constant.COMPRESS_POINT_SIZE;
    }
    for (let i = 0; i < this.r.length; i++) {
      bytes.set(this.r[i].compress(), offset);
      offset += constant.COMPRESS_POINT_SIZE;
    }
    bytes.set(this.a.toArray("be", constant.BIG_INT_SIZE), offset);
    offset += constant.BIG_INT_SIZE;
    bytes.set(this.b.toArray("be", constant.BIG_INT_SIZE), offset);
    offset += constant.BIG_INT_SIZE;
    bytes.set(this.p.compress(), offset);
    return bytes
  }

  setBytes(bytes) {
    if (bytes.length === 0) {
      return null
    }
    let lenLArray = bytes[0];
    let offset = 1;
    this.l = new Array(lenLArray);
    for (let i = 0; i < lenLArray; i++) {
      this.l[i] = p256.decompress(bytes.slice(offset, offset + constant.COMPRESS_POINT_SIZE));
      offset = offset + constant.COMPRESS_POINT_SIZE;
    }
    this.r = new Array(lenLArray);
    for (let i = 0; i < lenLArray; i++) {
      this.r[i] = p256.decompress(bytes.slice(offset, offset + constant.COMPRESS_POINT_SIZE));
      offset = offset + constant.COMPRESS_POINT_SIZE;
    }
    this.a = new BigInt(bytes.slice(offset, offset + constant.BIG_INT_SIZE), 16, "be");
    offset = offset + constant.BIG_INT_SIZE;
    this.b = new BigInt(bytes.slice(offset, offset + constant.BIG_INT_SIZE), 16, "be");
    offset = offset + constant.BIG_INT_SIZE;
    this.p = p256.decompress(bytes.slice(offset, offset + constant.COMPRESS_POINT_SIZE));
  }

  verify(AggParameter) {
    let p = this.p;
    let n = AggParameter.G.length;
    let G = new Array(n);
    let H = new Array(n);
    for (let i = 0; i < n; i++) {
      G[i] = AggParameter.G[i];
      H[i] = AggParameter.H[i];
    }
    let lLength = this.l.length;
    for (let i = 0; i < lLength; i++) {
      let nPrime = n / 2;
      let x = aggParams.generateChallengeForAggRange(AggParameter, [p.compress(), this.l[i].compress(), this.r[i].compress()]);
      let xInverse = x.invm(p256.n);
      let GPrime = new Array(nPrime);
      let HPrime = new Array(nPrime);
      for (let i = 0; i < nPrime; i++) {
        GPrime[i] = G[i].mul(xInverse).add(G[i + nPrime].mul(x));
        HPrime[i] = H[i].mul(x).add(H[i + nPrime].mul(xInverse));
      }
      let xSquare = x.mul(x);
      let xSquareInverse = xSquare.invm(p256.n);
      // x^2 * l + P + xInverse^2 * r
      p = this.l[i].mul(xSquare).add(p).add(this.r[i].mul(xSquareInverse));
      G = GPrime;
      H = HPrime;
      n = nPrime;
    }
    let c = this.a.mul(this.b);
    let rightPoint = G[0].mul(this.a);
    rightPoint = rightPoint.add(H[0].mul(this.b));
    rightPoint = rightPoint.add(AggParameter.U.mul(c));
    if (rightPoint.getX().cmp(p.getX()) === 0 && rightPoint.getY().cmp(p.getY()) === 0) {
      return true;
    }
    return false;
  }
}

function innerProduct(a, b) {
  if (a.length !== b.length) {
    return null
  }

  let c = new BigInt("0", 10);
  for (let i = 0; i < a.length; i++) {
    let tmp = a[i].mul(b[i]);
    c = c.add(tmp);
  }
  c = c.umod(p256.n);
  return c;
}

function vectorAdd(v, w) {
  if (v.length !== w.length) {
    return null
  }
  let result = new Array(v.length);
  for (let i = 0; i < v.length; i++) {
    result[i] = v[i].add(w[i]);
    result[i] = result[i].umod(p256.n)
  }
  return result
}

function hadamardProduct(v, w) {
  if (v.length !== w.length) {
    //privacy.NewPrivacyErr(privacy.UnexpectedErr, errors.New("hadamardProduct: Uh oh! Arrays not of the same length"))
  }

  let result = new Array(v.length);

  for (let i = 0; i < v.length; i++) {
    result[i] = v[i].mul(w[i]);
    result[i] = result[i].umod(p256.n);
  }
  return result
}

function vectorAddScalar(v, s) {
  result = new Array(v.length);
  for (let i = 0; i < v.length; i++) {
    result[i] = v[i].add(s);
    result[i] = result[i].umod(p256.n);
  }
  return result
}

function vectorMulScalar(v, s) {
  result = new Array(v.length);
  for (let i = 0; i < v.length; i++) {
    result[i] = v[i].mul(s);
    result[i] = result[i].umod(p256.n);
  }
  return result
}

function padLeft(str, pad, l) {
  let strCopy = str;
  while (strCopy.length < l) {
    strCopy = pad + strCopy
  }
  return strCopy
}

function strToBigIntArray(str) {
  result = new Array(str.length);
  for (let i = 0; i < str.length; i++) {
    result[i] = new BigInt(str[i], 10);
  }
  return result
}

function reverse(arr) {
  let result = new Array(arr.length);
  let leng = arr.length;
  for (let i = 0; i < arr.length; i++) {
    result[i] = arr[leng - i - 1]
  }
  return result
}

function powerVector(base, l) {
  let result = new Array(l.length);
  result[0] = new BigInt("1");
  for (let i = 1; i < l; i++) {
    result[i] = base.mul(result[i - 1]);
    result[i] = result[i].umod(p256.n);
  }
  return result;
}

function randVector(l) {
  let result = new Array(l.length);
  for (let i = 0; i < l; i++) {
    x = utils.RandInt(32);
    x = x.umod(p256.n);
    result[i] = x
  }
  return result
}

function vectorSum(y) {
  result = new BigInt("0", 10);
  for (let j = 0; j < y.length; j++) {
    result = result.add(new BigInt(j));
    result = result.umod(p256.n)
  }
  return result
}


function pad(l) {
  let deg = 0;
  while (l > 0) {
    if (l % 2 === 0) {
      deg++;
      l = l >> 1;
    } else {
      break;
    }
  }
  let i = 0;
  for (; ;) {
    if (Math.pow(2, i) < l) {
      i++;
    } else {
      l = Math.pow(2, i + deg);
      break;
    }
  }
  return l;

}


module.exports = {
  innerProductWitness,
  pad,
  powerVector,
  vectorAddScalar,
  vectorMulScalar,
  vectorAdd,
  hadamardProduct,
  innerProduct,
  innerProductProof
};
