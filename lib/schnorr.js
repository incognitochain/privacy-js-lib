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
    getPublicKey(GGenerator, HGenerator) {
        let G = P256.decompress(GGenerator);
        let H = P256.decompress(HGenerator);
        let PK = (G.mul(this.SK)).add(H.mul(this.R));
        let res = new Uint8Array(constants.COMPRESS_POINT_SIZE * 3);
        res.set(PK.compress(), 0);
        res.set(GGenerator, constants.COMPRESS_POINT_SIZE);
        res.set(HGenerator, constants.COMPRESS_POINT_SIZE * 2);
        return res;
    }
    sign(data) {
        if (data.length != constants.HASH_SIZE) {
            throw new Error("Hash length must be 32");
        }
        let s1 = new BigInt(utils.randScalar());
        let s2 = new BigInt(utils.randScalar());
        let t = (this.R == 0) ? (this.PK.G.mul(k.toRed(ec.N).fromRed())) : (this.PK.G.mul(k.toRed(ec.N).fromRed())).add(this.PK.H.mul(s2.toRed(ec.N).fromRed()));
        let E = hash(t, data);
        let Z1 = s1.toRed(ec.N).redSub(this.SK.toRed(ec.N).redMul(E.toRed(ec.N))).fromRed();
        if (this.R != 0) {
            let Z2 = s2.toRed(ec.N).redSub(this.R.toRed(ec.N).redMul(E.toRed(ec.N))).fromRed();
            let res = new Uint8Array(constants.BIG_INT_SIZE * 3);
            res.set(E.toArray('be', constants.BIG_INT_SIZE), 0);
            res.set(Z1.toArray('be', constants.BIG_INT_SIZE), constants.BIG_INT_SIZE);
            res.set(Z2.toArray('be', constants.BIG_INT_SIZE), constants.BIG_INT_SIZE * 2);
            return res;
        } else {
            let res = new Uint8Array(constants.BIG_INT_SIZE * 2);
            res.set(E.toArray('be', constants.BIG_INT_SIZE), 0);
            res.set(Z1.toArray('be', constants.BIG_INT_SIZE), constants.BIG_INT_SIZE);
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
    verify(signaturesBytesArrays, data) {
        let E = new BigInt(signaturesBytesArrays.slice(0, constants.BIG_INT_SIZE), 10, 'be');
        let S1 = new BigInt(signaturesBytesArrays.slice(constants.BIG_INT_SIZE, 2 * constants.BIG_INT_SIZE), 10, 'be');
        if (signaturesBytesArrays.length == constants.BIG_INT_SIZE * 2) {
            let rv = (this.PK.mul(E)).add(this.G.mul(S1));
            let ev = Hash(rv, data);
            return E.eq(ev);
        }
        let S2 = new BigInt(signaturesBytesArrays.slice(constants.BIG_INT_SIZE * 2, 3 * constants.BIG_INT_SIZE), 10, 'be');
        let rv = (this.PK.mul(E)).add(this.H.mul(S2)).add(this.G.mul(S1));
        let ev = hash(rv, data);
        return E.eq(ev);
    }
}

function hash(point, bytes) {
    let b = new Uint8Array(constants.BIG_INT_SIZE * 2 + bytes.length);
    b.set(point.getX().toArray('be', constants.BIG_INT_SIZE), 0);
    b.set(point.getY().toArray('be', constants.BIG_INT_SIZE), constants.BIG_INT_SIZE);
    b.set(bytes, constants.BIG_INT_SIZE * 2);
    return new BigInt(utils.hashBytesToBytes(b));
}

module.exports = {
    SchnPrivKey,
    SchnPubKey
}