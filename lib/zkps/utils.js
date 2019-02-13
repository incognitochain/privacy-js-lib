var common = require("../common");
var constants = require("../constants");
var PedCom = require("../pedersen").PedCom;
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

// it is not right for Golang
function Test(){
    let point = P256.decompress([3, 200, 234, 186, 139, 189, 103, 63, 205, 46, 5, 67, 135, 100, 82, 162, 254, 50, 30, 209, 97, 4, 225, 144, 204, 73, 61, 72, 201, 65, 228, 76, 42]);
    console.log(point);
}

Test();

module.exports = {
    generateChallenge
}