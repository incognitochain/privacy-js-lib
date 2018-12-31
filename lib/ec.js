var common = require("./common");
var Curve = new common.Elliptic('p256');
var utils = require('./privacy_utils');
var Base = common.ECC.curve;

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

if (Base.base.BasePoint.prototype.inverse){
    console.warn("Overriding existing Base.base.BasePoint.prototype.inverse. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.inverse = function() {
    var resY = Curve.curve.p.clone().sub(this.getY().clone());
    resY.red = null;
    return Curve.curve.point(this.getX().clone(), resY);
}

if (Base.base.BasePoint.prototype.issafe){
    console.warn("Overriding existing Base.base.BasePoint.prototype.issafe. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.issafe = function() {
    if (!Curve.curve.isoncurve(this))
        return false;
    return !this.dbl().isInfinity();
}

if (Base.base.BasePoint.prototype.compress){
    console.warn("Overriding existing Base.base.BasePoint.prototype.compress. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.compress = function() {
    var res = new Uint8Array(CompressPointSize);
    var y = this.getY().toArray('be', BigIntSize);
    res[0]=2 + (y[BigIntSize-1] & 1 );
    res.set(this.getX().toArray('be', BigIntSize), 1);
    return res;
}

if (Base.base.BasePoint.prototype.hash){
    console.warn("Overriding existing Base.base.BasePoint.prototype.hash. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.hash = function(index) {
    var x = this.getX();
    var l = new common.BigInt(100);
    var y = new common.BigInt(0);
    x = x.addn(index);
    var counter = 0;
    while (true) {
        counter++;
        x = new common.BigInt(common.DoubleHashBytesToBytes(x.toArray('be',BigIntSize)));
        y = x.toRed(moduleP).redPow(new common.BigInt(3)).fromRed();
        y = y.toRed(moduleP).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).fromRed();
        y = y.toRed(moduleP).redAdd(P256Base.toRed(moduleP)).fromRed();
        xCube = y.clone();
        y = y.toRed(moduleP).redPow(exp4SqrtModP).fromRed();
        if (!y.toRed(moduleP).redMul(y.toRed(moduleP)).fromRed().eq(xCube)){
            continue;
        }
        var res = Curve.curve.point(x,y);
        if (res.issafe()){
            return res;
        }
    }
}

if (Base.base.prototype.decompress){
    console.warn("Overriding existing Base.base.prototype.decompress. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.prototype.decompress = function(compBytes) {
    x = new common.BigInt(compBytes.slice(1,compBytes.length), '10', 'be');
    var y = new common.BigInt(0);
    var basePoint = P256Base.clone();
    y = x.toRed(moduleP).redPow(new common.BigInt(3)).fromRed();
    y = y.toRed(moduleP).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).fromRed();
    y = y.toRed(moduleP).redAdd(basePoint.toRed(moduleP)).fromRed();
    y = y.toRed(moduleP).redPow(exp4SqrtModP).fromRed();
    if (y.clone().modn(2) !== (compBytes[0] - 2)){
        y = Curve.curve.p.clone().sub(y);
    }
    return Curve.curve.point(x,y);
}

if (Base.base.prototype.randomize){
    console.warn("Overriding existing Base.base.prototype.randomize. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.prototype.randomize = function() {
    x = new common.BigInt(utils.RandBytes(BigIntSize));
    var y = new common.BigInt(0);
    var basePoint = P256Base.clone();
    y = x.toRed(moduleP).redPow(new common.BigInt(3)).fromRed();
    y = y.toRed(moduleP).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).fromRed();
    y = y.toRed(moduleP).redAdd(basePoint.toRed(moduleP)).fromRed();
    y = y.toRed(moduleP).redPow(exp4SqrtModP).fromRed();
    if (Math.floor(Math.random() * 256) % 2){
        y = Curve.curve.p.clone().sub(y);
    }
    return  Curve.curve.point(x,y);
}

if (Base.base.prototype.isoncurve){
    console.warn("Overriding existing Base.base.prototype.isoncurve. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.prototype.isoncurve = function(point) {
    var x = point.getX();
    var y = point.getY();
    return (y.toRed(moduleP).redMul(y.toRed(moduleP)).fromRed()).cmp(x.toRed(moduleP).redPow(new common.BigInt(3)).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).redAdd(P256Base.toRed(moduleP)).fromRed())===0;
}

var g1 = Curve.curve.randomize();
console.log("Test random decompress", Curve.curve.decompress(g1.compress()).eq(g1));
// module.exports = { moduleN, moduleP, P256Base, Curve, Compress, CompressPointSize, BigIntSize, Decompress, Sub, IsOnCurve, IsSafe, Inverse, IsEqual}
module.exports = { moduleN, moduleP, P256Base, Curve, CompressPointSize, BigIntSize}