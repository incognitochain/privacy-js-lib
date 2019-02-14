let common = require("./common");
let P256 = new common.Elliptic('p256');
let utils = require('./privacy_utils');
let Base = common.ECC.curve;
let cs = require("./constants");
let base58 = require('./base58');

const moduleP = common.BigInt.red(P256.curve.p.clone());
const moduleN = common.BigInt.red(P256.n.clone());

if (Base.base.BasePoint.prototype.inverse) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.inverse. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.inverse = function () {
    let resY = P256.curve.p.clone().sub(this.getY().clone());
    resY.red = null;
    return P256.curve.point(this.getX().clone(), resY);
}

if (Base.base.BasePoint.prototype.issafe) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.issafe. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.issafe = function () {
    return (P256.isoncurve(this)) ? (!this.dbl().isInfinity()) : (false);
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
        tmp = common.HashBytesToBytes(tmp);
        let x = new common.BigInt(tmp);
        try {
            res = P256.curve.pointFromX(x, false);
        } catch (error) {
            res = null
        }
        if ((res != null) && (res.issafe())) {
            return res;
        }
    }
}

if (Base.base.BasePoint.prototype.derive) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.derive. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.derive = function (seed, derivator) {
    return (this.issafe() ? this.mul((seed.toRed(moduleN).redAdd(derivator.toRed(moduleN))).redInvm().fromRed()) : null);
}

if (Base.base.BasePoint.prototype.marshalJSON) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.marshalJSON. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.marshalJSON = function () {
    let stringJSON = JSON.stringify(base58.CheckEncode(this.compress(), 0x00));
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
    let x = new common.BigInt(compBytes.slice(1, compBytes.length), '10', 'be');
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
    let res = base58.CheckDecode(JSON.parse(stringJSON));
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
    while (true) {
        let x = new common.BigInt(utils.RandBytes(cs.BigIntSize));
        try {
            res = P256.curve.pointFromX(x, Math.floor(Math.random() * 256) % 2);
        } catch (error) {
            res = null;
        }
        if ((res != null) && (res.issafe())) {
            return res;
        }
    }
}

if (P256.isoncurve) {
    console.warn("Overriding existing Base.base.prototype.isoncurve. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.isoncurve = function (point) {
    let x = point.getX();
    let y = point.getY();
    return (y.toRed(moduleP).redMul(y.toRed(moduleP)).fromRed()).cmp(x.toRed(moduleP).redPow(new common.BigInt(3)).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).redAdd(P256.B.toRed(moduleP)).fromRed()) === 0;
}

P256.B = new common.BigInt('41058363725152142129326129780047268409114441015993725554835256314039467401291', 10);
P256.pointFromX = P256.curve.pointFromX;
P256.p = P256.curve.p.clone();

module.exports = {moduleN, moduleP, P256};