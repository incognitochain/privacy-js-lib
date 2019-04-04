let ECC = require('elliptic');
let Elliptic = ECC.ec;
let BN = require('bn.js');
let P256 = new Elliptic('p256');
let utils = require('./privacy_utils');
let Base = ECC.curve;
let cs = require("./constants");
let bigIntUtils = require("./bigint_utils")

const P = BN.red(P256.curve.p.clone());
const N = BN.red(P256.n.clone());

ECC.curve.short.prototype.pointFromX = function pointFromX(x, odd = null) {
    x = new BN(x, 16);
    if (!x.red)
        x = x.toRed(this.red);

    var y2 = x.redSqr().redMul(x).redIAdd(x.redMul(this.a)).redIAdd(this.b);
    var y = y2.redSqrt();
    if (y.redSqr().redSub(y2).cmp(this.zero) !== 0)
        throw new Error('invalid point');
    if (odd != null) {
        var isOdd = y.fromRed().isOdd();
        if (odd && !isOdd || !odd && isOdd)
            y = y.redNeg();
    }
    return this.point(x, y);
};

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
    return (y.toRed(P).redMul(y.toRed(P)).fromRed()).cmp(x.toRed(P).redPow(new BN(3)).redSub(x.toRed(P).redMul((new BN(3)).toRed(P))).redAdd(P256.B.toRed(P)).fromRed()) === 0;
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
    let res = new Uint8Array(cs.COMPRESS_POINT_SIZE);
    res.set((this.getX().toArray('be', cs.BIG_INT_SIZE)), 1);
    res[0] = 2 + this.getY().isOdd();
    return res;
}

if (Base.base.BasePoint.prototype.hash) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.hash. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}
Base.base.BasePoint.prototype.hash = function (index) {
    let tmp = utils.addPaddingBigInt(this.getX(), cs.BIG_INT_SIZE);
    let indexBytes;
    if (index == 0) {
        indexBytes = [0];
    } else {
        indexBytes = new BN(index).toArray();
    }

    let bytes = new Uint8Array(cs.BIG_INT_SIZE + indexBytes.length)

    bytes.set(tmp, 0);
    bytes.set(indexBytes, cs.BIG_INT_SIZE);

    let res = null;
    while (true) {
        bytes = utils.hashSha3BytesToBytes(bytes);
        let x = new BN(bytes);
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

// const n = BigInt(P256.n.toString())
Base.base.BasePoint.prototype.derive = function (seed, derivator) {
    let result = null;
    try {
        // if (this.isSafe()) {
        //     console.time("1.1");
            let temp;
            temp = (seed.toRed(N).redAdd(derivator.toRed(N)))
            temp = temp.redInvm().fromRed();
            // console.timeEnd("1.1");
            result = this.mul(temp)
        // }
    } catch (e) {
        console.log("ERR1", e);
    }

    /*try {
        // if (this.isSafe()) {
        //     console.time("1.2");
            let temp;
            temp = (BigInt(seed.toString()) + BigInt(derivator.toString()));
            temp = bigIntUtils.modInverse(temp, n);
            // console.timeEnd("1.2")
            result = this.mul(new BN(temp.toString()));
        // }
    } catch (e) {
        console.log("ERR2", e);
    }*/

    return result;
};

/*if (Base.base.BasePoint.prototype.deriveOptimized) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.deriveOptimized. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}
Base.base.BasePoint.prototype.deriveOptimized = function (seed, derivator) {
    let result = null;
    try {
        // if (this.isSafe()) {
        //     console.time("1.2");
            let temp = seed + derivator;
            temp = bigIntUtils.modInverse(temp, n);
            // console.timeEnd("1.2")
            result = this.mulOptimized(temp);
        // }
    } catch (e) {
        console.log("ERR2", e);
    }
    return result;
};
if (Base.base.BasePoint.prototype.mulOptimized) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.mulOptimized. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}
// scalar is BigInt
Base.base.BasePoint.prototype.mulOptimized = function (scalar){
    let scalarTmp = scalar;
    let pointTmp = this;
    let twoBN = BigInt(2);
    let result = P256.curve.point(0, 0);
    let resultNull = true;
    // check point is double point or not
    // if point is double point:  check scalar is even or odd
    if (this.dbl().isInfinity()){
        if (scalarTmp % twoBN == 0){
            return result;
        } else{
            return pointTmp;
        }
    } else{
        while (scalarTmp > 0){
            let bin = scalarTmp % twoBN;
            scalarTmp = scalarTmp / twoBN;
            if (bin == 1){
                if (!resultNull){
                    result = result.addOptimized(pointTmp);
                }else{
                    result = pointTmp;
                    resultNull = false
                }
            }
            pointTmp = pointTmp.dbl();
        }
    }
    return result;
}

if (Base.base.BasePoint.prototype.addOptimized) {
    console.warn("Overriding existing Base.base.BasePoint.prototype.derive. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}
// scalar is BigInt
Base.base.BasePoint.prototype.addOptimized = function (p){
    // console.time("addOptimized")
    // O + P = P
    // console.time("pre")
    if (this.inf) {
        // console.timeEnd("addOptimized")
        return p;
    }
    // P + O = P
    if (p.inf) {
        // console.timeEnd("addOptimized")
        return this;
    }
    // P + P = 2P
    if (this.eq(p)) {
        // console.timeEnd("addOptimized")
        return this.dbl();
    }
    // P + (-P) = O
    // if (this.neg().eq(p))
    //   return this.curve.point(null, null);
    let n = BigInt(this.curve.p.toString());
    // P + Q = O
    if (this.x.cmp(p.x) === 0) {
        // console.timeEnd("addOptimized")
        return this.curve.point(null, null);
    }
    // console.timeEnd("pre")
    // console.time("Declare")
    let px = BigInt(p.x.fromRed().toString())
    let x = BigInt(this.x.fromRed().toString())
    let y = BigInt(this.y.fromRed().toString())
    let py = BigInt(p.y.fromRed().toString())
    let c = y - py
    // console.timeEnd("Declare")
    // console.time("Ver2")
    if (c != 0) {
        c = c * bigIntUtils.modInverse(bigIntUtils.umod(x - px, n), n)
        // c = umod(c,n)
    }
    const nx = bigIntUtils.umod(((c * c) - x) - px, n)
    const ny = bigIntUtils.umod(c * (x - nx) - y, n);
    // console.timeEnd("Ver2")
    // console.time("Ver2 Parse")
    const ctx = BN.mont(this.curve.p)
    const res = this.curve.point(new BN(nx.toString()).toRed(ctx), new BN(ny.toString()).toRed(ctx));
    // console.timeEnd("Ver2 Parse")
    // console.timeEnd("addOptimized")
    return res;
}*/

if (P256.decompress) {
    console.warn("Overriding existing Base.base.prototype.decompress. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.decompress = function (compBytes) {
    if (compBytes.length != cs.COMPRESS_POINT_SIZE) {
        throw new Error("Decompress failed! Bytes in inputs is not bytes of compressed point!");
    }
    x = new BN(compBytes.slice(1, compBytes.length), '10', 'be');
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

if (P256.randomize) {
    console.warn("Overriding existing Base.base.prototype.randomize. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.randomize = function () {
    let res = null;
    while (1) {
        x = new BN(utils.randBytes(cs.BIG_INT_SIZE));
        try {
            res = P256.curve.pointFromX(x, utils.randBytes(1)[0] & 1);
        } catch (error) {
            res = null;
        }
        if ((res != null) && (res.isSafe())) {
            return res;
        }
    }
}

P256.B = new BN('41058363725152142129326129780047268409114441015993725554835256314039467401291', 10);
P256.pointFromX = P256.curve.pointFromX;
P256.p = P256.curve.p.clone();
module.exports = {
    N,
    P,
    P256,
    add,
};

function add() {
    console.log("abababababab")
}
