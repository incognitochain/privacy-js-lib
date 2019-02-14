var PedCom = require("../pedersen").PedCom;
var common = require("../common");
var bal_utils = require("./aggregatedrange_utils");
var P256 = new common.Elliptic('p256');
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
    res = P256.curve.point(0, 0);
    for (let i=0;i<a.length;i++){
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
        bytes.set(AggParam.G[i].compress(),offset);
        offset+=constants.CompressPointSize;
    }
    for (let i=0;i<AggParam.H.length;i++){
        bytes.set(AggParam.H[i].compress(),offset);
        offset+=constants.CompressPointSize;
    }
    bytes.set(AggParam.U.compress(),offset);
    offset+=constants.CompressPointSize;
    for (let i=0;i<values.length;i++){
        bytes.set(values[i]);
        offset+=values[i].length
    }
    let hash = common.HashBytesToBytes(bytes);
    res = new common.BigInt("0");
    res = new common.BigInt(hash, 16, "be");
    res = res.umod(P256.n);
    return res;
}
module.exports ={BulletproofParams,generateChallengeForAggRange,EncodeVectors};
