var common = require("./common");
var ec = require("./ec.js");
var pcparamsInitCounters = 0;
const Capacity = 5
class PCParams {
    constructor(){
        if (pcparamsInitCounters!==0){
            throw new Error("Just init once time!");
        };
        pcparamsInitCounters++;
        var G1 = ec.P256.curve.point(ec.P256.g.getX(),ec.P256.g.getY());
        this.G = new Array(G1);
        for (var i=1; i<Capacity; i++){
            this.G.push(this.G[i-1].hash(i));
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
        var res = this.G[0].mul(Openings[0]);
        for (var i =0; i< Capacity; i++){
            res = res.add(this.G[i].mul(Openings[i]));
        };
        return res;
    };
    CommitAtIndex(value, rand, index) {
        return (this.G[Capacity-1].mul(rand)).add(this.G[index].mul(value));
    }
}

var PedCom = new PCParams();

module.exports = {PedCom, Capacity}