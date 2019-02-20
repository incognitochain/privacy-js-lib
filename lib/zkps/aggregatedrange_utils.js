let BigInt = require('bn.js');
let utils = require('../privacy_utils');
let constant = require('../constants');
let ec = require('elliptic').ec;
let p256 = new ec('p256');
let zeroPoint = p256.curve.point(0, 0);
let aggParams = require("./aggregaterangeparams");

class innerProductWitness {
    constructor() {
        this.a = [];
        this.b = [];
        this.p = zeroPoint
    }

    prove(AggParam) {
        if (this.a.length !== this.b.length) {
            return null
        }
        let n = this.a.length;
        let a = [];
        let b = [];
        for (let i = 0; i < n; i++) {
            a[i] = this.a[i];
            b[i] = this.b[i];
        }
        let p = p256.curve.point(this.p.getX(), this.p.getY());
        let G = [];
        let H = [];
        for (let i = 0; i < n; i++) {
            G[i] = p256.curve.point(AggParam.G[i].getX(), AggParam.G[i].getY());
            H[i] = p256.curve.point(AggParam.H[i].getX(), AggParam.H[i].getY());
        }
        let proof = new innerProductProof();
        proof.l = [];
        proof.r = [];
        proof.p = this.p;
        while (n > 1) {
            let nPrime = n / 2;
            let cL = innerProduct(a.slice(0, nPrime), b.slice(nPrime,));
            let cR = innerProduct(a.slice(nPrime,), b.slice(0, nPrime));
            let L = aggParams.EncodeVectors(a.slice(0, nPrime), b.slice(nPrime,), G.slice(nPrime,), H.slice(0, nPrime));
            L = L.add(AggParam.U.mul(cL));
            proof.l = proof.l.concat(L);
            let R = aggParams.EncodeVectors(a.slice(nPrime,), b.slice(0, nPrime), G.slice(0, nPrime), H.slice(nPrime,));
            R = R.add(AggParam.U.mul(cR));
            proof.r = proof.r.concat(R);
            // calculate challenge x = hash(G || H || u || p ||  l || r)
            let values = [];
            values[0] = p.compress();
            values[1] = L.compress();
            values[2] = R.compress();
            let x = aggParams.generateChallengeForAggRange(AggParam, values);
            let xInverse = x.invm(p256.n);
            let GPrime = [];
            let HPrime = [];
            for (let i = 0; i < nPrime; i++) {
                GPrime[i] = G[i].mul(xInverse).add(G[i + nPrime].mul(x));
                HPrime[i] = H[i].mul(x).add(H[i + nPrime].mul(xInverse));
            }
            let xSquare = x.mul(x);
            let xSquareInverse = xSquare.invm(p256.n);
            let PPrime = L.mul(xSquare).add(p).add(R.mul(xSquareInverse));

            // calculate aPrime, bPrime
            let aPrime = [];
            let bPrime = [];

            for (let i = 0; i < nPrime; i++) {
                aPrime[i] = a[i].mul(x);
                aPrime[i] = aPrime[i].add(a[i + nPrime].mul(xInverse));
                aPrime[i] = aPrime[i].umod(p256.n);

                bPrime[i] = b[i].mul(xInverse);
                bPrime[i] = bPrime[i].add(b[i + nPrime].mul(x));
                bPrime[i] = bPrime[i].umod(p256.n);
            }

            a = aPrime;
            b = bPrime;
            p = p256.curve.point(PPrime.getX(), PPrime.getY());
            G = GPrime;
            H = HPrime;
            n = nPrime;
        }

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
        this.l = [];
        for (let i = 0; i < lenLArray; i++) {
            this.l[i] = p256.curve.point(0, 0);
            this.l[i].decompress(bytes.slice(offset, offset + constant.COMPRESS_POINT_SIZE));
            offset = offset + constant.COMPRESS_POINT_SIZE;
        }
        this.L = [];
        for (let i = 0; i < lenLArray; i++) {
            this.r[i] = p256.curve.point(0, 0);
            this.r[i].decompress(bytes.slice(offset, offset + constant.COMPRESS_POINT_SIZE));
            offset = offset + constant.COMPRESS_POINT_SIZE;
        }
        this.a = new BigInt(bytes.slice(offset, offset + constant.BIG_INT_SIZE), 16, "be");
        offset = offset + constant.BIG_INT_SIZE;
        this.b = new BigInt(bytes.slice(offset, offset + constant.BIG_INT_SIZE), 16, "be");
        offset = offset + constant.BIG_INT_SIZE;
        this.p = p256.curve.point(0, 0);
        this.p.decompress(bytes.slice(offset, offset + constant.COMPRESS_POINT_SIZE));
    }
    verify(AggParameter) {
        let p = this.p;
        let n = AggParameter.G.length;
        let G = [];
        let H = [];
        for (let i = 0; i < n; i++) {
            G[i] = AggParameter.G[i];
            H[i] = AggParameter.H[i];
        }
        let lLength = this.l.length;
        for (let i = 0; i < lLength; i++) {
            let nPrime = n / 2;
            let x = aggParams.generateChallengeForAggRange(AggParameter, [p.compress(), this.l[i].compress(), this.r[i].compress()])
            let xInverse = x.invm(p256.n);
            let GPrime = [];
            let HPrime = [];
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
    let result = [];
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

    let result = [];

    for (let i = 0; i < v.length; i++) {
        result[i] = v[i].mul(w[i]);
        result[i] = result[i].umod(p256.n);
    }
    return result
}

function vectorAddScalar(v, s) {
    result = [];
    for (let i = 0; i < v.length; i++) {
        result[i] = v[i].add(s);
        result[i] = result[i].umod(p256.n);
    }
    return result
}

function vectorMulScalar(v, s) {
    result = [];
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
    result = [];
    for (let i = 0; i < str.length; i++) {
        result[i] = new BigInt(str[i], 10);
    }
    return result
}

function reverse(arr) {
    let result = [];
    let leng = arr.length;
    for (let i = 0; i < arr.length; i++) {
        result[i] = arr[leng - i - 1]
    }
    return result
}

function powerVector(base, l) {
    let result = [];
    result[0] = new BigInt("1");
    for (let i = 1; i < l; i++) {
        result[i] = base.mul(result[i - 1]);
        result[i] = result[i].umod(p256.n);
    }
    return result;
}

function randVector(l) {
    let result = [];
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
    for (;;) {
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
    reverse,
    strToBigIntArray,
    padLeft,
    vectorAddScalar,
    randVector,
    vectorMulScalar,
    vectorAdd,
    hadamardProduct,
    innerProduct,
    innerProductProof
};
//
// // x = new CryptoParams().InitCryptoParams(5,64);
// // console.log(x);
// // a = new BigInt("112903417795660718437322609784741174137436221623070734970718620502234785130587",10);
// // x= a.toString(10,null);
// // x = a.toBuffer("be", 77)
// // console.log(stringToBytes(x));
// // b = new BigInt("492",10);
// // console.log(b.toString(10,null));
// // y = b.toBuffer("be", 32)
// // console.log(y);
// // z = Buffer.concat([x,y]);
// // console.log(common.hashBytesToBytes(z));
//
// // a = new BigInt("47515829744028368076079098769021912108834233286729163024982797332997787453512",10);
// // b = new BigInt("87002542642193967023996021196060015663269581560271645134905725961626816885860",10);
// // c = new BigInt("43649401850892143763726554215752408353114045232054668349034459406587646176686",10);
// // d = new BigInt("70610724445527920943403872361121863038966490300463643114484538886656446460160",10);
// // z = a.toString(10,null) + b.toString(10,null)+c.toString(10,null)+d.toString(10,null)
// // console.log(common.hashBytesToBytes(utils.stringToBytes(z)));
// // z = [148, 5, 25, 99, 19, 192, 184, 176, 81, 215, 221, 166, 179, 63, 185, 72, 45 ,126, 121, 90 ,68 ,199, 98, 36, 112, 37, 112, 87, 25, 121, 43, 231]
// // console.log(utils.ByteArrToInt(z).toString(10,null));
// // let x = 5
// // a = new BigInt(x);
// // b = a.add(new BigInt('3'));
// // console.log(a.toString(10,null),a.add(new BigInt('3')).toString(10,null));