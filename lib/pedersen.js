const { PC_CAPACITY, COMPRESS_POINT_SIZE, RAND } = require('./constants');
const { P256 } = require('./ec');
let pcparamsInitCounters = 0;

class PedersenCommitmentParams {
    constructor() {
        if (pcparamsInitCounters !== 0) {
            throw new Error("Just init once time!");
        };

        pcparamsInitCounters++;
        this.G = new Array(PC_CAPACITY);
        this.GBytes = new Uint8Array(PC_CAPACITY * COMPRESS_POINT_SIZE);
        this.G[0] = P256.curve.point(P256.g.getX(), P256.g.getY());
        this.GBytes.set(this.G[0].compress(), 0);

        for (let i = 1; i < PC_CAPACITY; i++) {
            this.G[i] = this.G[0].hash(i);
            this.GBytes.set(this.G[i].compress(), i * COMPRESS_POINT_SIZE);
        };
    };

    get() {
        if (pcparamsInitCounters === 0) {
            return new PedersenCommitmentParams();
        };
        return this.G;
    };

    commitAll(openings) {
        if (openings.length !== PC_CAPACITY) {
            throw new Error("Length of openings is less than Capacity, CommitAll function requires ", PC_CAPACITY, " openings.");
        };
        let res = this.G[0].mul(openings[0]);
        for (let i = 1; i < PC_CAPACITY; i++) {
            res = res.add(this.G[i].mul(openings[i]));
        };
        return res;
    };

    commitAtIndex(value, rand, index) {
        return (this.G[RAND].mul(rand)).add(this.G[index].mul(value));
    }
}

const PedCom = new PedersenCommitmentParams();

module.exports = {
    PedCom
};