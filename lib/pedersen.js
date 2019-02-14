let common = require('./common');
let cs = require('./constants');
let P256 = require('./ec').P256;
let pcparamsInitCounters = 0;
const Capacity = 5
class PCParams {
    constructor() {
        if (pcparamsInitCounters !== 0) {
            throw new Error("Just init once time!");
        };
        pcparamsInitCounters++;
        this.G = new Array(Capacity);
        this.G[0] = P256.curve.point(P256.g.getX(), P256.g.getY());
        for (let i = 1; i < Capacity; i++) {
            this.G[i] = this.G[0].hash(i);
        };
    };
    Get() {
        if (pcparamsInitCounters === 0) {
            return new PCParams();
        };
        return this.G;
    };
    CommitAll(Openings) {
        if (Openings.length !== Capacity) {
            throw new Error("Length of Openings is less than Capacity, CommitAll function requires ", Capacity, " openings.");
        };
        let res = this.G[0].mul(Openings[0]);
        for (let i = 1; i < Capacity; i++) {
            res = res.add(this.G[i].mul(Openings[i]));
        };
        return res;
    };
    CommitAtIndex(value, rand, index) {
        return (this.G[cs.RAND].mul(rand)).add(this.G[index].mul(value));
    }
}

const PedCom = new PCParams();

// for (let i=0; i<Capacity; i++){
//     console.log("G[",i,"]: ",PedCom.G[i].getX().toString(),PedCom.G[i].getY().toString());
// }

module.exports = {
    PedCom,
    Capacity
};