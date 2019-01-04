var common = require("./common");
var P256 = new common.Elliptic('p256');
var utils = require('./privacy_utils');
var Base = common.ECC.curve;
var cs = require("./constants")

const moduleP = common.BigInt.red(P256.curve.p.clone());
const moduleN = common.BigInt.red(P256.n.clone());
const exp4SqrtModP = P256.curve.p.clone().addn(1).divn(4);// Fyi: To understanding that, read Tonelli–Shanks algorithm on Wikipedia.

if (Base.base.BasePoint.prototype.inverse){
    console.warn("Overriding existing Base.base.BasePoint.prototype.inverse. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.inverse = function() {
    var resY = P256.curve.p.clone().sub(this.getY().clone());
    resY.red = null;
    return P256.curve.point(this.getX().clone(), resY);
}

if (Base.base.BasePoint.prototype.issafe){
    console.warn("Overriding existing Base.base.BasePoint.prototype.issafe. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.issafe = function() {
    if (!P256.isoncurve(this))
        return false;
    return !this.dbl().isInfinity();
}

if (Base.base.BasePoint.prototype.compress){
    console.warn("Overriding existing Base.base.BasePoint.prototype.compress. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.compress = function() {
    var res = new Uint8Array(cs.CompressPointSize);
    var y = this.getY().toArray('be', cs.BigIntSize);
    res[0]=2 + (y[cs.BigIntSize-1] & 1 );
    res.set(this.getX().toArray('be', cs.BigIntSize), 1);
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
        x = new common.BigInt(common.DoubleHashBytesToBytes(x.toArray('be',cs.BigIntSize)));
        y = x.toRed(moduleP).redPow(new common.BigInt(3)).fromRed();
        y = y.toRed(moduleP).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).fromRed();
        y = y.toRed(moduleP).redAdd(P256.B.toRed(moduleP)).fromRed();
        xCube = y.clone();
        y = y.toRed(moduleP).redPow(exp4SqrtModP).fromRed();
        if (!y.toRed(moduleP).redMul(y.toRed(moduleP)).fromRed().eq(xCube)){
            continue;
        }
        var res = P256.curve.point(x,y);
        if (res.issafe()){
            return res;
        }
    }
}

if (P256.decompress){
    console.warn("Overriding existing Base.base.prototype.decompress. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.decompress = function(compBytes) {
    x = new common.BigInt(compBytes.slice(1,compBytes.length), '10', 'be');
    var y = new common.BigInt(0);
    var basePoint = P256.B.clone();
    y = x.toRed(moduleP).redPow(new common.BigInt(3)).fromRed();
    y = y.toRed(moduleP).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).fromRed();
    y = y.toRed(moduleP).redAdd(basePoint.toRed(moduleP)).fromRed();
    y = y.toRed(moduleP).redPow(exp4SqrtModP).fromRed();
    if (y.clone().modn(2) !== (compBytes[0] - 2)){
        y = P256.curve.p.clone().sub(y);
    }
    return P256.curve.point(x,y);
}

if (P256.randomize){
    console.warn("Overriding existing Base.base.prototype.randomize. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.randomize = function() {
    x = new common.BigInt(utils.RandBytes(cs.BigIntSize));
    var y = new common.BigInt(0);
    var basePoint = P256.B.clone();
    y = x.toRed(moduleP).redPow(new common.BigInt(3)).fromRed();
    y = y.toRed(moduleP).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).fromRed();
    y = y.toRed(moduleP).redAdd(basePoint.toRed(moduleP)).fromRed();
    y = y.toRed(moduleP).redPow(exp4SqrtModP).fromRed();
    if (Math.floor(Math.random() * 256) % 2){
        y = P256.curve.p.clone().sub(y);
    }
    return  P256.curve.point(x,y);
}

if (P256.isoncurve){
    console.warn("Overriding existing Base.base.prototype.isoncurve. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.isoncurve = function(point) {
    var x = point.getX();
    var y = point.getY();
    return (y.toRed(moduleP).redMul(y.toRed(moduleP)).fromRed()).cmp(x.toRed(moduleP).redPow(new common.BigInt(3)).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).redAdd(P256.B.toRed(moduleP)).fromRed())===0;
}

P256.B = new common.BigInt('41058363725152142129326129780047268409114441015993725554835256314039467401291',10);

P256.p = P256.curve.p.clone();

console.log(P256.isoncurve(P256.g));

var g1 = P256.randomize();
listPoint = new Array(P256.g);
console.log(utils.generateChallengeFromPoint(listPoint).toRed(moduleN).fromRed().toString())
console.log("Test random decompress", P256.decompress(g1.compress()).eq(g1));
// module.exports = { moduleN, moduleP, P256.B, P256, Compress, cs.CompressPointSize, cs.BigIntSize, Decompress, Sub, IsOnCurve, IsSafe, Inverse, IsEqual}
module.exports = { moduleN, moduleP, P256};