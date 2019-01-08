var common = require('../common');
var ec = require('../ec');
var P256 = require('../ec').P256;
var aggRange = require('./aggregatedrange');
var zeroCom = require('./zerocommitment');

class PaymentWitness {
    constructor() {
        this.spendingKey = new common.BigInt(0);
        this.RandSK = new common.BigInt(0);
        this.inputCoins = [];               // []*privacy.InputCoin
        this.outputCoins = [];              // []*privacy.OutputCoin
        this.commitmentIndices = [];        // []uint64
        this.myCommitmentIndices = [];      // []uint64

        this.OneOfManyWitness = [];         // []*OneOutOfManyWitness
        this.SerialNumberWitness = [];      // []*PKSNPrivacyWitness
        this.SNNoPrivacyWitness = [];       // []*SNNoPrivacyWitness

        this.ComOutputMultiRangeWitness = new aggRange.AggregatedRangeWitness();
        this.ComZeroWitness = new zeroCom.ComZeroWitness();

        this.ComOutputValue = [];           // []*privacy.EllipticPoint
        this.ComOutputSND = [];             // []*privacy.EllipticPoint
        this.ComOutputShardID = [];         // []*privacy.EllipticPoint

        this.ComInputSK = new P256.curve.point();
        this.ComInputValue = [];            // []*privacy.EllipticPoint
        this.ComInputSND = [];              // []*privacy.EllipticPoint
    }

    init(hasPrivacy, senderSK, inputCoins, outputCoins, pkLastByteSender, commitmentProving, commitmentIndexs, myCommitmentIndexs, fee) {
        return this;
    }

    prove(hasPrivacy) {
        return new PaymentProof();
    }
}

class PaymentProof {
    constructor() {
        return this;
    }

    toBytes() {
        return [];
    }
}

module.exports = {PaymentWitness, PaymentProof};