let ECC = require('elliptic');
let Elliptic = ECC.ec;
let BigInt = require('bn.js');
let P256 = new Elliptic('p256');
let utils = require('./privacy_utils');
let Base = ECC.curve;
let cs = require("./constants");
let base58 = require('./base58');

const P = BigInt.red(P256.curve.p.clone());
const N = BigInt.red(P256.n.clone());

if (Base.base.BasePoint.prototype.inverse) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.inverse. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.inverse = function () {
    let resY = P256.curve.p.clone().sub(this.getY().clone());
    resY.red = null;
    return P256.curve.point(this.getX().clone(), resY);
}

if (P256.isOnCurve) {
    console.warn("Overriding existing Base.base.prototype.isOnCurve. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.isOnCurve = function (point) {
    let x = point.getX();
    let y = point.getY();
    return (y.toRed(P).redMul(y.toRed(P)).fromRed()).cmp(x.toRed(P).redPow(new BigInt(3)).redSub(x.toRed(P).redMul((new BigInt(3)).toRed(P))).redAdd(P256.B.toRed(P)).fromRed()) === 0;
}

if (Base.base.BasePoint.prototype.isSafe) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.isSafe. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.isSafe = function () {
    return (P256.isOnCurve(this)) ? (!this.dbl().isInfinity()) : (false);
}

if (Base.base.BasePoint.prototype.sub) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.sub. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.sub = function (point) {
    return this.add(point.inverse());
}

if (Base.base.BasePoint.prototype.compress) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.compress. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.compress = function () {
    let res = new Uint8Array(cs.CompressPointSize);
    res.set((this.getX().toArray('be', cs.BigIntSize)), 1);
    res[0] = 2 + this.getY().isOdd();
    return res;
}

if (Base.base.BasePoint.prototype.hash) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.hash. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}
Base.base.BasePoint.prototype.hash = function (index) {
    let tmp = this.getX().toArray();
    tmp.push(index);
    let res = null;
    while (true) {
        tmp = utils.hashBytesToBytes(tmp);
        let x = new BigInt(tmp);
        try {
            res = P256.curve.pointFromX(x);
        } catch (error) {
            res = null
        }
        if ((res != null) && (res.isSafe())) {
            return res;
        }
    }
}

if (Base.base.BasePoint.prototype.derive) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.derive. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.derive = function (seed, derivator) {
    return (this.isSafe() ? this.mul((seed.toRed(N).redAdd(derivator.toRed(N))).redInvm().fromRed()) : null);
}

if (Base.base.BasePoint.prototype.marshalJSON) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.marshalJSON. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.marshalJSON = function () {
    let stringJSON = JSON.stringify(base58.checkEncode(this.compress(), 0x00));
    let res = new Uint8Array(stringJSON.length);
    for (let i = 0; i < stringJSON.length; i++) {
        res[i] = stringJSON.charCodeAt(i);
    }
    return res;
}

if (P256.decompress) {
    console.warn("Overriding existing Base.base.prototype.decompress. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.decompress = function (compBytes) {
    if (compBytes.length != cs.CompressPointSize) {
        throw new Error("Decompress failed! Bytes in inputs is not bytes of compressed point!");
    }
    x = new BigInt(compBytes.slice(1, compBytes.length), '10', 'be');
    let res = null;
    try {
        res = P256.curve.pointFromX(x, compBytes[0] - 2);
    } catch (error) {
        console.log(error);
        throw error;
    } finally {
        return res;
    }
}

if (P256.unmarshalJSON) {
    console.warn("Overriding existing Base.base.prototype.unmarshalJSON. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.unmarshalJSON = function (data) {
    let stringJSON = new String();
    for (let i = 0; i < data.length; i++) {
        stringJSON += String.fromCharCode(data[i]);
    }
    let res = base58.checkDecode(JSON.parse(stringJSON));
    if (res.version != 0x00) {
        throw new Error("Decode failed! Wrong version!");
    }
    return P256.decompress(res.bytesDecoded);
}

if (P256.randomize) {
    console.warn("Overriding existing Base.base.prototype.randomize. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.randomize = function () {
    let res = null;
    while (1) {
        x = new BigInt(utils.RandBytes(cs.BigIntSize));
        try {
            res = P256.curve.pointFromX(x, utils.RandBytes(1)[0] & 1);
        } catch (error) {
            res = null;
        }
        if ((res != null) && (res.isSafe())) {
            return res;
        }
    }
}

P256.B = new BigInt('41058363725152142129326129780047268409114441015993725554835256314039467401291', 10);
P256.pointFromX = P256.curve.pointFromX;
P256.p = P256.curve.p.clone();
module.exports = {
    N,
    P,
    P256
};