let BigInt = require('bn.js');
let PedCom = require("../pedersen").PedCom;
let ec = require('../ec');
let utils = require('../privacy_utils');
let P256 = ec.P256;

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
    let hash = utils.HashBytesToBytes(bytes);
    let res = new BigInt(hash, 10);
    res.umod(P256.n);
    return res
}

module.exports = {
    generateChallenge
}

//     let values =[[38,182,245,255,88,71,47,10,115,26,170,82,236,162,201,123,200,13,250,151,214,25,218,187,168,209,63,19,234,0,54,0],
//     [72,61,92,58,58,29,10,79,54,224,61,8,8,144,178,208,72,114,250,27,117,144,123,150,201,64,26,91,229,71,74,9],
//     [248,79,103,162,8,4,98,59,194,232,126,96,246,93,252,23,252,50,182,42,209,216,89,114,234,194,14,76,75,160,225,111],
//     [133,38,172,236,51,55,146,102,135,105,14,214,206,69,138,133,103,121,34,94,190,29,244,126,118,137,137,255,74,196,226,250]];
// console.log(generateChallenge(values).toString(10));