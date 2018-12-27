var common = require("./common");
var ec = require("./ec.js");
var crypto = require("crypto");
// PK = G^SK + H^Randomness
class SchnPrivKey { 
    constructor(privateKeyBytesArrays) {
        this.SK = new common.BigInt(privateKeyBytesArrays.slice(0,ec.BigIntSize));
        this.R = new common.BigInt(privateKeyBytesArrays.slice(ec.BigIntSize, ec.BigIntSize*2));
        this.PK = this.GetPublicKey(privateKeyBytesArrays.slice(ec.BigIntSize*2, ec.BigIntSize*2 + ec.CompressPointSize),privateKeyBytesArrays.slice(ec.BigIntSize*2 + ec.CompressPointSize, ec.BigIntSize*2 + ec.CompressPointSize*2));
    }
    GetPublicKey(GGenerator, HGenerator) {
        G = ec.Decompress(GGenerator);
        H = ec.Decompress(HGenerator);
        var res = new Uint8Array(ec.CompressPointSize*3);
        var PK = G.mul(this.SK).add(H.mul(this.R));
        res.set(ec.Compress(PK),0);
        res.set(GGenerator,ec.CompressPointSize);
        res.set(HGenerator,ec.CompressPointSize*2);
        return res;

    }
    Sign(data){
        var k1 = new common.BigInt(crypto.randomBytes(32),10,'be');
        var k2 = new common.BigInt(crypto.randomBytes(32),10,'be');
        var t = this.G.mul(k1).add(this.H.mul(k2));
        
        //Add Hash soon
        var E = Hash(t, data);
        
        // xe = Sk * e
        var xe = this.SK.clone().mul(E);
        var S1 = k1.toRed(ec.moduleN).redSub(xe.toRed(ec.moduleN)).fromRed();
        
        // re = Randomness * e
        var re = this.R.clone().mul(E);
        var S2 = k2.toRed(ec.moduleN).redSub(re.toRed(ec.moduleN)).fromRed();
    
        var res = new Uint8Array(ec.BigIntSize + ec.CompressPointSize*2);
        res.set(E.toArray('be',ec.BigIntSize), 0);
        res.set(S1.toArray('be',ec.BigIntSize), ec.BigIntSize);
        res.set(S2.toArray('be',ec.BigIntSize), ec.BigIntSize*2);

        return res;
    }
}
class SchnPubKey {
    constructor(publicKeyBytesArrays){
        this.PK = ec.Decompress(publicKeyBytesArrays[0, ec.CompressPointSize]);
        this.G = ec.Decompress(publicKeyBytesArrays[ec.CompressPointSize, ec.CompressPointSize*2]);
        this.H = ec.Decompress(publicKeyBytesArrays[ec.CompressPointSize*2, ec.CompressPointSize*3]);
    }
    Verify(signaturesBytesArrays, data) {
        var E = new common.BigInt(signaturesBytesArrays.slice(0, ec.BigIntSize), 10, 'be');
        var S1 = new common.BigInt(signaturesBytesArrays.slice(ec.BigIntSize, 2*ec.BigIntSize), 10, 'be');
        var S2 = new common.BigInt(signaturesBytesArrays.slice(ec.BigIntSize*2, 3*ec.BigIntSize), 10, 'be');
        var rv = this.PK.mul(E).add(this.H.mul(S2)).add(this.G.mul(S1));
        var ev = Hash(rv, data);
        return E.eq(ev);
    }
}

module.exports = {SchnPrivKey, SchnPubKey}