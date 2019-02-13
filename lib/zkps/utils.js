var common = require("../common");
var constants = require("../constants");
var PedCom = require("../pedersen").PedCom;
// var P256 = new common.Elliptic('p256');
let ec = require('../ec');
let P256 = ec.P256;

function generateChallenge(values){
    let bytes = PedCom.G[0].compress();
    for (let i=1;i<PedCom.G.length;i++){
        bytes.concat(PedCom.G[i].compress());
    }
    for (let i=0;i<values.length;i++){
        bytes.concat(values[i])
    }
    let hash =  common.HashBytesToBytes(bytes);
    let res = new common.BigInt(bytes,10);
    res.umod(P256.n);
    return res
}


module.exports = {
    generateChallenge
}