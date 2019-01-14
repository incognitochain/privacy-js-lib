let common = require("./common");
let P256 = require("./ec.js").P256;
let PubParams = require("./publicparams").PubParams;
let pcparamsInitCounters = 0;
const Capacity = 5
class PCParams {
    constructor(){
        if (pcparamsInitCounters!==0){
            throw new Error("Just init once time!");
        };
        pcparamsInitCounters++;
        this.G = new Array(Capacity);
        for (let i=0; i<Capacity; i++){
            this.G[i] = P256.curve.point(PubParams.G[i].getX(),PubParams.G[i].getY());
        };
    };
    Get(){
        if (pcparamsInitCounters === 0){
            return new PCParams();
        };
        return this.G;
    };
    CommitAll(Openings){
        if (Openings.length !== Capacity) {
            throw new Error("Length of Openings is less than Capacity, CommitAll function requires ", Capacity," openings.");
        };
        let res = this.G[0].mul(Openings[0]);
        for (let i =0; i< Capacity; i++){
            res = res.add(this.G[i].mul(Openings[i]));
        };
        return res;
    };
    CommitAtIndex(value, rand, index) {
        return (this.G[Capacity-1].mul(rand)).add(this.G[index].mul(value));
    }
}

const PedCom = new PCParams();
console.log(PedCom.G)
module.exports = {PedCom, Capacity}