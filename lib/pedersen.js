let cs = require('./constants');
let P256 = require('./ec').P256;
let pcparamsInitCounters = 0;
class PCParams {
    constructor() {
        if (pcparamsInitCounters !== 0) {
            throw new Error("Just init once time!");
        };
        pcparamsInitCounters++;
        this.G = new Array(cs.PCCapacity);
        this.GBytes = new Uint8Array(cs.PCCapacity * cs.CompressPointSize);
        this.G[0] = P256.curve.point(P256.g.getX(), P256.g.getY());
        this.GBytes.set(this.G[0].compress(), 0);
        for (let i = 1; i < cs.PCCapacity; i++) {
            this.G[i] = this.G[0].hash(i);
            this.GBytes.set(this.G[i].compress(), i * cs.CompressPointSize);
        };
    };
    get() {
        if (pcparamsInitCounters === 0) {
            return new PCParams();
        };
        return this.G;
    };
    commitAll(Openings) {
        if (Openings.length !== cs.PCCapacity) {
            throw new Error("Length of Openings is less than Capacity, CommitAll function requires ", cs.PCCapacity, " openings.");
        };
        let res = this.G[0].mul(Openings[0]);
        for (let i = 1; i < cs.PCCapacity; i++) {
            res = res.add(this.G[i].mul(Openings[i]));
        };
        return res;
    };
    commitAtIndex(value, rand, index) {
        return (this.G[cs.RAND].mul(rand)).add(this.G[index].mul(value));
    }
}

const PedCom = new PCParams();

module.exports = {
    PedCom
};