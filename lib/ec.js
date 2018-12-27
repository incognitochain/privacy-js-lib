var common = require("./common");
var Curve = new common.Elliptic('p256');

const P256Base = new common.BigInt('41058363725152142129326129780047268409114441015993725554835256314039467401291',10);
const CompressPointSize = 33;
const BigIntSize = 32;
const moduleP = common.BigInt.red(Curve.curve.p.clone());
const moduleN = common.BigInt.red(Curve.n.clone());
const exp4SqrtModP = Curve.curve.p.clone().addn(1).divn(4);// Fyi: To understanding that, read Tonelli–Shanks algorithm on Wikipedia.

// Compress: input: curve.point, output: bytearrays with 33byte length
function Compress(point) {
    var res = new Uint8Array(CompressPointSize);
    var y = point.getY().toArray('be', BigIntSize);
    res[0]=2 + (y[BigIntSize-1] & 1 );
    res.set(point.getX().toArray('be', BigIntSize), 1);
    return res;
}

// Decompress: input: bytearrays with 33byte length, out: curve.point
function Decompress(compPoint) {
    x = new common.BigInt(compPoint.subarray(1), '10', 'be');
    var y = new common.BigInt(0);
    var basePoint = P256Base.clone();
    y = x.toRed(moduleP).redPow(new common.BigInt(3)).fromRed();
    y = y.toRed(moduleP).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).fromRed();
    y = y.toRed(moduleP).redAdd(basePoint.toRed(moduleP)).fromRed();
    y = y.toRed(moduleP).redPow(exp4SqrtModP).fromRed();
    var res = Curve.curve.point(x,y);
    return res;
}

function IsOnCurve(point) {
    var x = point.getX();
    var y = point.getY();
    var basePoint = P256Base.clone();
    return (y.toRed(moduleP).redMul(y.toRed(moduleP)).fromRed()).cmp(x.toRed(moduleP).redPow(new common.BigInt(3)).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).redAdd(basePoint.toRed(moduleP)).fromRed())===0;
}

function Inverse(point) {
    var resX = point.getX().clone();
    var resY = point.getY().clone();
    resY = Curve.curve.p.clone().sub(resY);
    resY.red = null;
    return Curve.curve.point(resX, resY)
}

function Sub(srcPoint, dstPoint) {
    return srcPoint.add(Inverse(dstPoint));
}

function IsEqual(p1, p2) {
    return (p1.getX().cmp(p2.getX()) + p1.getY().cmp(p2.getY())) === 0;
}

function IsSafe(point) {
    if (!IsOnCurve(point))
        return fasle;
    return !point.dbl().isInfinity();
}

var p192 = new common.BigInt(50);
var m = common.BigInt.red(p192);
var a = new common.BigInt(90);
var b = new common.BigInt(20);
var c = a.toRed(m).redAdd(b.toRed(m)).fromRed();
console.log(c.cmp(a.add(b).mod(p192)) === 0);

module.exports = { moduleN, moduleP, P256Base, Curve, Compress, CompressPointSize, BigIntSize, Decompress, Sub, IsOnCurve, IsSafe, Inverse, IsEqual}