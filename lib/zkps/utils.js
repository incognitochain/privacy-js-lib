const bn = require('bn.js');
const { PedCom } = require("../pedersen");
const { P256 } = require('../ec');
const { hashSha3BytesToBytes } = require('../privacy_utils');

function generateChallenge(values) {
    let l = PedCom.GBytes.length;
    let offset = PedCom.GBytes.length;
    for (let i = 0; i < values.length; i++) {
        l += values[i].length;
    }
    let bytes = new Uint8Array(l);
    bytes.set(PedCom.GBytes, 0);

    for (let i = 0; i < values.length; i++) {
        bytes.set(values[i], offset);
        offset += values[i].length;
    }
    let hash = hashSha3BytesToBytes(bytes);
    let res = new bn(hash, 10);
    res = res.umod(P256.n);
    return res
}

module.exports = {
  generateChallenge
}