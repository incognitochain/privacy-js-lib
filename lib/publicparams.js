let P256 = require("./ec.js").P256;
let publicparamsInitCounters = 0;
const Capacity = 133;
class PublicParams {
    constructor(){
        if (publicparamsInitCounters!==0){
            throw new Error("Just init once time!");
        };
        publicparamsInitCounters++;
        let G1 = P256.curve.point(P256.g.getX(),P256.g.getY());
        this.G = new Array(Capacity);
        for (let i=0; i<Capacity; i++){
            this.G[i] = G1.hash(i);
        };
    };
};
const PubParams = new PublicParams();
module.exports = {PubParams, Capacity}