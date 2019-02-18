let PedCom = require("../pedersen").PedCom;
let common = require("../common");
let bal_utils = require("./aggregatedrange_utils");
let P256 = new common.Elliptic('p256');
let constants = require('../constants');
class BulletproofParams {
    constructor(m) {
        this.G = [];
        this.H = [];
        let capacity = 64 * m;
        for (let i=0;i<capacity;i++){
            this.G[i] = PedCom.G[0].hash(5+i);
            this.H[i] = PedCom.G[0].hash(5+i+capacity);
        }
        this.U = this.H[0].hash(5+2*capacity)
    }
}
function EncodeVectors(a,b,g,h) {
    if (a.length !== b.length || g.length !== h.length || a.length !== g.length){
        return null
    }
    res = (g[0].mul(a[0])).add(h[0].mul(b[0]));
    for (let i=1;i<a.length;i++){
        res = res.add(g[i].mul(a[i])).add(h[i].mul(b[i]))
    }
    return res
}
function generateChallengeForAggRange(AggParam,values) {
    l = (AggParam.G.length + AggParam.H.length + 1)*constants.CompressPointSize;
    for (let i=0;i<values.length;i++){
        l+=values[i].length
    }
    let bytes = new Uint8Array(l);
    let offset = 0;
    for (let i=0;i<AggParam.G.length;i++){
        let b = AggParam.G[i].compress();
        bytes.set(b,offset);
        offset+=constants.CompressPointSize;
    }
    for (let i=0;i<AggParam.H.length;i++){
        bytes.set(AggParam.H[i].compress(),offset);
        offset+=constants.CompressPointSize;
    }
    bytes.set(AggParam.U.compress(),offset);
    offset+=constants.CompressPointSize;
    for (let i=0;i<values.length;i++){
        bytes.set(values[i],offset);
        offset+=values[i].length
    }
    let hash = common.HashBytesToBytes(bytes);
    res = new common.BigInt("0");
    res = new common.BigInt(hash, 16, "be");
    res = res.umod(P256.n);
    return res;
}
module.exports ={BulletproofParams,generateChallengeForAggRange,EncodeVectors};
// let G1 = PedCom.G[0].hash(5);
// console.log(G1.compress());
// for (let i=0;i<5;i++){
//     let bytes = PedCom.G[0].hash(5+i).compress();
//     let str = "[";
//     for (let b in bytes){
//         str = str + " " + new String(bytes[b])
//     }
//     console.log(str+ "]")
// }