var common = require("./common");
var ec = require("./ec.js");
var utils = require("./privacy_utils");
// PK = G^SK + H^Randomness
class SchnPrivKey { 
    constructor(privateKeyBytesArrays) {
        this.SK = new common.BigInt(privateKeyBytesArrays.slice(0,ec.BigIntSize));
        this.R = new common.BigInt(privateKeyBytesArrays.slice(ec.BigIntSize, ec.BigIntSize*2));
        this.PK = new SchnPubKey(this.GetPublicKey(privateKeyBytesArrays.slice(ec.BigIntSize*2, ec.BigIntSize*2 + ec.CompressPointSize),privateKeyBytesArrays.slice(ec.BigIntSize*2 + ec.CompressPointSize, ec.BigIntSize*2 + ec.CompressPointSize*2)));
    }
    GetPublicKey(GGenerator, HGenerator) {
        var G = ec.P256.decompress(GGenerator);
        var H = ec.P256.decompress(HGenerator);
        var res = new Uint8Array(ec.CompressPointSize*3);
        var PK = (G.mul(this.SK)).add(H.mul(this.R));
        res.set(PK.compress(),0);
        res.set(GGenerator,ec.CompressPointSize);
        res.set(HGenerator,ec.CompressPointSize*2);
        return res;

    }
    Sign(data){
        var k1 = new common.BigInt(utils.RandBytes(32),10,'be');
        var k2 = new common.BigInt(utils.RandBytes(32),10,'be');
        // var k1 = new common.BigInt(12344543232);
        // var k2 = new common.BigInt(12344543231);
        var t = (this.PK.G.mul(k1.toRed(ec.moduleN).fromRed())).add(this.PK.H.mul(k2.toRed(ec.moduleN).fromRed()));
        // console.log(t.getX().toString(), " ", t.getY().toString());
        //Add Hash soon
        var E = Hash(t, data);
        
        // xe = Sk * e
        var xe = this.SK.toRed(ec.moduleN).redMul(E.toRed(ec.moduleN)).fromRed();
        var S1 = k1.toRed(ec.moduleN).redSub(xe.toRed(ec.moduleN));

        // re = Randomness * e
        var re = this.R.toRed(ec.moduleN).redMul(E.toRed(ec.moduleN)).fromRed();
        var S2 = k2.toRed(ec.moduleN).redSub(re.toRed(ec.moduleN));

        var res = new Uint8Array(ec.BigIntSize*3);
        res.set(E.toArray('be',ec.BigIntSize), 0);
        res.set(S1.toArray('be',ec.BigIntSize), ec.BigIntSize);
        res.set(S2.toArray('be',ec.BigIntSize), ec.BigIntSize*2);
        return res;
    }
}
class SchnPubKey {
    constructor(publicKeyBytesArrays){
        this.PK = ec.P256.decompress(publicKeyBytesArrays.slice(0, ec.CompressPointSize));
        this.G = ec.P256.decompress(publicKeyBytesArrays.slice(ec.CompressPointSize, ec.CompressPointSize*2));
        this.H = ec.P256.decompress(publicKeyBytesArrays.slice(ec.CompressPointSize*2, ec.CompressPointSize*3));
    }
    Verify(signaturesBytesArrays, data) {
        var E = new common.BigInt(signaturesBytesArrays.slice(0, ec.BigIntSize), 10, 'be');
        var S1 = new common.BigInt(signaturesBytesArrays.slice(ec.BigIntSize, 2*ec.BigIntSize), 10, 'be');
        var S2 = new common.BigInt(signaturesBytesArrays.slice(ec.BigIntSize*2, 3*ec.BigIntSize), 10, 'be');
        var rv = (this.PK.mul(E)).add(this.H.mul(S2)).add(this.G.mul(S1));
        var ev = Hash(rv, data);
        return E.eq(ev);
    }
}

function Hash(point, bytes){
    var b = new Uint8Array(ec.BigIntSize*2 + bytes.length);
    b.set(point.getX().toArray('be', ec.BigIntSize),0);
    b.set(point.getY().toArray('be', ec.BigIntSize),ec.BigIntSize);
    b.set(bytes,ec.BigIntSize*2);
    return new common.BigInt(common.HashBytesToBytes(b),10,'be');
}

var privKey = new SchnPrivKey([70,161,141,52,130,112,50,134,233,11,30,40,5,192,197,125,50,220,87,91,130,220,195,174,249,249,61,206,247,9,250,30,8,249,61,222,215,78,35,76,213,24,164,107,28,243,63,245,91,170,126,64,246,19,63,43,77,237,198,235,54,184,100,173,3,107,23,209,242,225,44,66,71,248,188,230,229,99,164,64,242,119,3,125,129,45,235,51,160,244,161,57,69,216,152,194,150,3,227,253,122,181,42,120,126,246,157,250,207,232,52,148,103,238,41,27,224,243,99,87,103,192,153,158,110,215,85,176,140,95]);
var data = [227,156,87,184,229,145,212,144,145,77,185,213,185,110,42,181,97,235,209,34,125,130,211,219,119,35,238,7,6,175,87,232];
var SignedData = privKey.Sign(data);
var res = privKey.PK.Verify(SignedData,data);

console.log("Test schnorr schemes: ", res);
module.exports = {SchnPrivKey, SchnPubKey}