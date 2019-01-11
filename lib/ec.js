let common = require("./common");
let P256 = new common.Elliptic('p256');
let utils = require('./privacy_utils');
let Base = common.ECC.curve;
let cs = require("./constants")

const moduleP = common.BigInt.red(P256.curve.p.clone());
const moduleN = common.BigInt.red(P256.n.clone());
const exp4SqrtModP = P256.curve.p.clone().addn(1).divn(4);// Fyi: To understanding that, read Tonelli–Shanks algorithm on Wikipedia.

if (Base.base.BasePoint.prototype.inverse){
    console.warn("Overriding existing Base.base.BasePoint.prototype.inverse. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.inverse = function() {
    let resY = P256.curve.p.clone().sub(this.getY().clone());
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
    let y = this.getY().toArray('be', cs.BigIntSize);
    let res = new Array();
    res = res.concat(2 + (y[cs.BigIntSize-1] & 1 )).concat(this.getX().toArray('be', cs.BigIntSize));
    return res;
}

if (Base.base.BasePoint.prototype.hash){
    console.warn("Overriding existing Base.base.BasePoint.prototype.hash. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.hash = function(index) {
    let x = this.getX();
    let l = new common.BigInt(100);
    let y = new common.BigInt(0);
    x = x.addn(index);
    let counter = 0;
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
        let res = P256.curve.point(x,y);
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
    let y = new common.BigInt(0);
    let basePoint = P256.B.clone();
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
    let res = P256.curve.point(0,0);
    while (1){
        x = new common.BigInt(utils.RandBytes(cs.BigIntSize));
        let y = new common.BigInt(0);
        let basePoint = P256.B.clone();
        y = x.toRed(moduleP).redPow(new common.BigInt(3)).fromRed();
        y = y.toRed(moduleP).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).fromRed();
        y = y.toRed(moduleP).redAdd(basePoint.toRed(moduleP)).fromRed();
        y = y.toRed(moduleP).redPow(exp4SqrtModP).fromRed();
        if (Math.floor(Math.random() * 256) % 2){
            y = P256.curve.p.clone().sub(y);
        }
        res = P256.curve.point(x,y);
        if (res.issafe()){
            return res;
        }
    }
}

if (P256.isoncurve){
    console.warn("Overriding existing Base.base.prototype.isoncurve. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.isoncurve = function(point) {
    let x = point.getX();
    let y = point.getY();
    return (y.toRed(moduleP).redMul(y.toRed(moduleP)).fromRed()).cmp(x.toRed(moduleP).redPow(new common.BigInt(3)).redSub(x.toRed(moduleP).redMul((new common.BigInt(3)).toRed(moduleP))).redAdd(P256.B.toRed(moduleP)).fromRed())===0;
}

P256.B = new common.BigInt('41058363725152142129326129780047268409114441015993725554835256314039467401291',10);

P256.p = P256.curve.p.clone();
//
// // console.log(P256.isoncurve(P256.g));
//
// let g1 = P256.randomize();
// listPoint = new Array(P256.g);
// console.log(utils.generateChallengeFromPoint(listPoint).toRed(moduleN).fromRed().toString())
// console.log("Compress: ",g1.compress());
// console.log("Test random decompress", P256.decompress(g1.compress()).eq(g1));


// module.exports = { moduleN, moduleP, P256.B, P256, Compress, cs.CompressPointSize, cs.BigIntSize, Decompress, Sub, IsOnCurve, IsSafe, Inverse, IsEqual}
module.exports = { moduleN, moduleP, P256};