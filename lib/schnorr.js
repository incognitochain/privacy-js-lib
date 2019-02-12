let common = require("./common");
let ec = require("./ec.js");
let utils = require("./privacy_utils");
let PedCom = require('./pedersen').PedCom;
let constants = require('./constants');
let P256 = ec.P256;

// PK = G^SK + H^Randomness
class SchnPrivKey { 
    // constructor(privateKeyBytesArrays) {
    //     this.SK = new common.BigInt(privateKeyBytesArrays.slice(0,constants.BigIntSize));
    //     this.R = new common.BigInt(privateKeyBytesArrays.slice(constants.BigIntSize, constants.BigIntSize*2));
    //     this.PK = new SchnPubKey(this.GetPublicKey(privateKeyBytesArrays.slice(constants.BigIntSize*2, constants.BigIntSize*2 + constants.CompressPointSize),privateKeyBytesArrays.slice(constants.BigIntSize*2 + constants.CompressPointSize, constants.BigIntSize*2 + constants.CompressPointSize*2)));
    // }
    constructor(sk, r){
        this.SK = sk;
        this.R = r;
        this.PK = new SchnPubKey();
        this.PK.G = PedCom.G[constants.SK];
        this.PK.H = PedCom.G[constants.RAND];
        this.PK.PK = this.PK.G.mul(this.SK).add(this.PK.H.mul(this.R))
    
    }
    GetPublicKey(GGenerator, HGenerator) {
        let G = P256.decompress(GGenerator);
        let H = P256.decompress(HGenerator);
        let PK = (G.mul(this.SK)).add(H.mul(this.R));
        let res = new Uint8Array(constants.CompressPointSize*3);
        res.set(PK.compress(),0);
        res.set(GGenerator,constants.CompressPointSize);
        res.set(HGenerator,constants.CompressPointSize*2);
        return res;//PK.compress().concat(GGenerator).concat(HGenerator);
    }
    Sign(data){
        if (data.length!=constants.HashSize){
            throw new Error("Hash length must be 32");
        }
        let s1 = new common.BigInt(utils.RandInt());
        let s2 = new common.BigInt(utils.RandInt());
        let t = (this.R == 0)?(this.PK.G.mul(k.toRed(ec.moduleN).fromRed())):(this.PK.G.mul(k.toRed(ec.moduleN).fromRed())).add(this.PK.H.mul(s2.toRed(ec.moduleN).fromRed()));
        let E = Hash(t, data);
        let Z1 = s1.toRed(ec.moduleN).redSub(this.SK.toRed(ec.moduleN).redMul(E.toRed(ec.moduleN))).fromRed();
        if (this.R != 0) {
            let Z2 = s2.toRed(ec.moduleN).redSub(this.R.toRed(ec.moduleN).redMul(E.toRed(ec.moduleN))).fromRed();
            let res = new Uint8Array(constants.BigIntSize*3);
            res.set(E.toArray('be',constants.BigIntSize), 0);
            res.set(Z1.toArray('be',constants.BigIntSize), constants.BigIntSize);
            res.set(Z2.toArray('be',constants.BigIntSize), constants.BigIntSize*2);
            return res;
        } else {
            let res = new Uint8Array(constants.BigIntSize*2);
            res.set(E.toArray('be',constants.BigIntSize), 0);
            res.set(Z1.toArray('be',constants.BigIntSize), constants.BigIntSize);
            return res;
        }
    }
}
class SchnPubKey {
    // constructor(publicKeyBytesArrays){
    //     this.PK = P256.decompress(publicKeyBytesArrays.slice(0, constants.CompressPointSize));
    //     this.G = P256.decompress(publicKeyBytesArrays.slice(constants.CompressPointSize, constants.CompressPointSize*2));
    //     this.H = P256.decompress(publicKeyBytesArrays.slice(constants.CompressPointSize*2, constants.CompressPointSize*3));
    // }
    constructor(PK, G, H){
        this.PK = PK;
        this.G = G;
        this.H = H;
    }
    Verify(signaturesBytesArrays, data) {
        let E = new common.BigInt(signaturesBytesArrays.slice(0, constants.BigIntSize), 10, 'be');
        let S1 = new common.BigInt(signaturesBytesArrays.slice(constants.BigIntSize, 2*constants.BigIntSize), 10, 'be');
        if (signaturesBytesArrays.length==constants.BigIntSize*2){
            let rv = (this.PK.mul(E)).add(this.G.mul(S1));
            let ev = Hash(rv, data);
            return E.eq(ev);
        }
        S2 = new common.BigInt(signaturesBytesArrays.slice(constants.BigIntSize*2, 3*constants.BigIntSize), 10, 'be');
        let rv = (this.PK.mul(E)).add(this.H.mul(S2)).add(this.G.mul(S1));
        let ev = Hash(rv, data);
        return E.eq(ev);
    }
}

function Hash(point, bytes){
    let b = new Uint8Array(constants.BigIntSize*2 + bytes.length);
    b.set(point.getX().toArray('be', constants.BigIntSize),0);
    b.set(point.getY().toArray('be', constants.BigIntSize),constants.BigIntSize);
    b.set(bytes,constants.BigIntSize*2);
    return new common.BigInt(common.HashBytesToBytes(b));
}

// let privKey = new SchnPrivKey([70,161,141,52,130,112,50,134,233,11,30,40,5,192,197,125,50,220,87,91,130,220,195,174,249,249,61,206,247,9,250,30,8,249,61,222,215,78,35,76,213,24,164,107,28,243,63,245,91,170,126,64,246,19,63,43,77,237,198,235,54,184,100,173,3,107,23,209,242,225,44,66,71,248,188,230,229,99,164,64,242,119,3,125,129,45,235,51,160,244,161,57,69,216,152,194,150,3,227,253,122,181,42,120,126,246,157,250,207,232,52,148,103,238,41,27,224,243,99,87,103,192,153,158,110,215,85,176,140,95]);
let privKey = new SchnPrivKey(utils.RandInt(32), utils.RandInt(32))
let data = [227,156,87,184,229,145,212,144,145,77,185,213,185,110,42,181,97,235,209,34,125,130,211,219,119,35,238,7,6,175,87,232];
let SignedData = privKey.Sign(data);
let res = privKey.PK.Verify(SignedData,data);
//
console.log("Test schnorr schemes: ", res);
module.exports = {SchnPrivKey, SchnPubKey}