const bn = require('bn.js');
const { PedCom } = require("../pedersen");
const { hashSha3BytesToBytes } = require('../privacy_utils');
const { COMPRESS_POINT_SIZE } = require('../constants');
const { P256 } = require('../ec');
const {MAX_EXP} = require('./constants');

class BulletproofParams {
    constructor(m) {
        if (m > 0) {
            let capacity = MAX_EXP * m;
            this.G = new Array(capacity);
            this.H = new Array(capacity);
            for (let i = 0; i < capacity; i++) {
                this.G[i] = PedCom.G[0].hash(5 + i);
                this.H[i] = PedCom.G[0].hash(5 + i + capacity);
            }
            this.U = this.H[0].hash(5 + 2 * capacity)
        } else{
            this.G = [];
            this.H = [];
            this.U = null;
        }
    }

    addBulletProofParams(extraNumber) {
        let currentCapacity = AggParam.G.length;
	    let newCapacity = currentCapacity + 64 * extraNumber

        for (let i = 0; i < newCapacity - currentCapacity; i++) {
            AggParam.G = AggParam.G.concat(privacy.PedCom.G[0].Hash(int64(5 + i + currentCapacity)))
            AggParam.G = AggParam.G.concat(privacy.PedCom.G[0].Hash(int64(5 + i + currentCapacity + maxOutputNumber*64)))
        }

        return AggParam
    }
}

const AggParam = new BulletproofParams(16);

function EncodeVectors(a, b, g, h) {
    if (a.length !== b.length || g.length !== h.length || a.length !== g.length) {
        return null
    }
    let res = (g[0].mul(a[0])).add(h[0].mul(b[0]));
    for (let i = 1; i < a.length; i++) {
        res = res.add(g[i].mul(a[i])).add(h[i].mul(b[i]))
    }
    return res
}

function generateChallengeForAggRange(AggParam, values) {
    l = (AggParam.G.length + AggParam.H.length + 1) * COMPRESS_POINT_SIZE;
    for (let i = 0; i < values.length; i++) {
        l += values[i].length
    }
    let bytes = new Uint8Array(l);
    let offset = 0;
    for (let i = 0; i < AggParam.G.length; i++) {
        let b = AggParam.G[i].compress();
        bytes.set(b, offset);
        offset += COMPRESS_POINT_SIZE;
    }
    for (let i = 0; i < AggParam.H.length; i++) {
        bytes.set(AggParam.H[i].compress(), offset);
        offset += COMPRESS_POINT_SIZE;
    }
    bytes.set(AggParam.U.compress(), offset);
    offset += COMPRESS_POINT_SIZE;
    for (let i = 0; i < values.length; i++) {
        bytes.set(values[i], offset);
        offset += values[i].length
    }
    let hash = hashSha3BytesToBytes(bytes);
    let res = new bn(hash, 16, "be");
    res = res.umod(P256.n);
    return res;
}
module.exports = {
    BulletproofParams,
    generateChallengeForAggRange,
    EncodeVectors,
    AggParam
};