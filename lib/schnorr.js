let BigInt = require('bn.js');
let ec = require("./ec.js");
let utils = require("./privacy_utils");
let PedCom = require('./pedersen').PedCom;
let constants = require('./constants');
let P256 = ec.P256;

// PK = G^SK + H^Randomness
class SchnPrivKey {
    constructor(sk, r) {
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
        let res = new Uint8Array(constants.CompressPointSize * 3);
        res.set(PK.compress(), 0);
        res.set(GGenerator, constants.CompressPointSize);
        res.set(HGenerator, constants.CompressPointSize * 2);
        return res;
    }
    Sign(data) {
        if (data.length != constants.HashSize) {
            throw new Error("Hash length must be 32");
        }
        let s1 = new BigInt(utils.RandScalar());
        let s2 = new BigInt(utils.RandScalar());
        let t = (this.R == 0) ? (this.PK.G.mul(k.toRed(ec.N).fromRed())) : (this.PK.G.mul(k.toRed(ec.N).fromRed())).add(this.PK.H.mul(s2.toRed(ec.N).fromRed()));
        let E = Hash(t, data);
        let Z1 = s1.toRed(ec.N).redSub(this.SK.toRed(ec.N).redMul(E.toRed(ec.N))).fromRed();
        if (this.R != 0) {
            let Z2 = s2.toRed(ec.N).redSub(this.R.toRed(ec.N).redMul(E.toRed(ec.N))).fromRed();
            let res = new Uint8Array(constants.BigIntSize * 3);
            res.set(E.toArray('be', constants.BigIntSize), 0);
            res.set(Z1.toArray('be', constants.BigIntSize), constants.BigIntSize);
            res.set(Z2.toArray('be', constants.BigIntSize), constants.BigIntSize * 2);
            return res;
        } else {
            let res = new Uint8Array(constants.BigIntSize * 2);
            res.set(E.toArray('be', constants.BigIntSize), 0);
            res.set(Z1.toArray('be', constants.BigIntSize), constants.BigIntSize);
            return res;
        }
    }
}
class SchnPubKey {
    constructor(PK, G, H) {
        this.PK = PK;
        this.G = G;
        this.H = H;
    }
    Verify(signaturesBytesArrays, data) {
        let E = new BigInt(signaturesBytesArrays.slice(0, constants.BigIntSize), 10, 'be');
        let S1 = new BigInt(signaturesBytesArrays.slice(constants.BigIntSize, 2 * constants.BigIntSize), 10, 'be');
        if (signaturesBytesArrays.length == constants.BigIntSize * 2) {
            let rv = (this.PK.mul(E)).add(this.G.mul(S1));
            let ev = Hash(rv, data);
            return E.eq(ev);
        }
        let S2 = new BigInt(signaturesBytesArrays.slice(constants.BigIntSize * 2, 3 * constants.BigIntSize), 10, 'be');
        let rv = (this.PK.mul(E)).add(this.H.mul(S2)).add(this.G.mul(S1));
        let ev = Hash(rv, data);
        return E.eq(ev);
    }
}

function Hash(point, bytes) {
    let b = new Uint8Array(constants.BigIntSize * 2 + bytes.length);
    b.set(point.getX().toArray('be', constants.BigIntSize), 0);
    b.set(point.getY().toArray('be', constants.BigIntSize), constants.BigIntSize);
    b.set(bytes, constants.BigIntSize * 2);
    return new BigInt(utils.HashBytesToBytes(b));
}

module.exports = {
    SchnPrivKey,
    SchnPubKey
}