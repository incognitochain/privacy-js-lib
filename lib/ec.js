let common = require("./common");
let P256 = new common.Elliptic('p256');
let utils = require('./privacy_utils');
let Base = common.ECC.curve;
let cs = require("./constants");
let base58 = require('./base58');

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
    while (true) {
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

if (Base.base.BasePoint.prototype.derive){
    console.warn("Overriding existing Base.base.BasePoint.prototype.derive. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.derive = function(seed, derivator) {
    return (this.issafe()?this.mul((seed.toRed(moduleN).redAdd(derivator.toRed(moduleN))).redInvm().fromRed()):null);
}

if (Base.base.BasePoint.prototype.marshalJSON){
    console.warn("Overriding existing Base.base.BasePoint.prototype.marshalJSON. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

Base.base.BasePoint.prototype.marshalJSON = function() {
    let stringJSON = JSON.stringify(base58.CheckEncode(this.compress(),0x00));
    let res = new Uint8Array(stringJSON.length);
    for (let i=0;i<stringJSON.length;i++){
        res[i] = stringJSON.charCodeAt(i);
    }
	return res;
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

if (P256.unmarshalJSON){
    console.warn("Overriding existing Base.base.prototype.unmarshalJSON. Possible causes: New API defines the method, there's a framework conflict or you've got double inclusions in your code.");
}

P256.unmarshalJSON = function(data) {
    let stringJSON = new String();
    for (let i=0; i<data.length;i++){
        stringJSON+=String.fromCharCode(data[i]);
    }
    let res = base58.CheckDecode(JSON.parse(stringJSON));
    if (res.version != 0x00){
        throw new Error("Decode failed! Wrong version!");
    }
    return P256.decompress(res.bytesDecoded);
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

module.exports = { moduleN, moduleP, P256};