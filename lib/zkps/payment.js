var common = require('../common');
var ec = require('../ec');
var P256 = ec.P256;
var aggRange = require('./aggregatedrange');
var zeroCom = require('./zerocommitment');
var pc = require('../pedersen');
var constants = require('../constants');

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

        this.ComInputSK = new P256.curve.point(0,0);
        this.ComInputValue = [];            // []*privacy.EllipticPoint
        this.ComInputSND = [];              // []*privacy.EllipticPoint
        this.ComInputShardID = new P256.curve.point(0,0);
    }

    init(hasPrivacy, spendingKey, inputCoins, outputCoins, pkLastByteSender, commitments, commitmentIndices, myCommitmentIndices, fee) {
        if (!hasPrivacy){
            for (var i =0; i<outputCoins.length; i++){
                outputCoins[i].Randomness = utils.RandInt();
                outputCoins[i].CoinDetails.CommitAll();
            }
            this.spendingKey = spendingKey;
            this.inputCoins = inputCoins;
            this.outputCoins = outputCoins;

            var publicKey = inputCoins[0].CoinDetails.PublicKey;

            for (let i = 0; i < inputCoins.length; i++) {
                /***** Build witness for proving that serial number is derived from the committed derivator *****/
                this.SNNoPrivacyWitness[i].set(inputCoins[i].CoinDetails.SerialNumber, publicKey, inputCoins[i].CoinDetails.SNDerivator, this.spendingKey)
            }
            return null
        }
        this.spendingKey = spendingKey;
        this.inputCoins = inputCoins;
        this.outputCoins = outputCoins;
        this.commitmentIndices = commitmentIndices;
        this.myCommitmentIndices = myCommitmentIndices;

        var numInputCoin = this.inputCoins.length;

        // save rand SK for Schnorr signature
        this.RandSK = utils.RandInt();
        // calculate sk commitment of input coins
        this.ComInputSK = pc.PedCom.CommitAtIndex(this.spendingKey, this.RandSK, constants.SK);

        var randInputShardID = utils.RandInt();
        // calculate shard id commitment of input coins
        this.ComInputShardID = pc.PedCom.CommitAtIndex(new common.BigInt(pkLastByteSender), randInputShardID, constants.SHARDID);

        var randInputValue = [];
        var randInputSND = [];
        var randInputSNDIndexSK = [];
        // It is used for proving 2 commitments commit to the same value (input)
        var cmInputSNDIndexSK = [];

        // cmInputValueAll is sum of all input coins' value commitments
        var cmInputValueAll = P256.curve.point(0,0);
        var randInputValueAll = new common.BigInt(0);

        // Summing all commitments of each input coin into one commitment and proving the knowledge of its Openings
        var cmInputSum = [];
        var randInputSum = [];

        // randInputSumAll is sum of all randomess of coin commitments
        var randInputSumAll = new common.BigInt(0);

        var commitmentTemps = [];
        var randInputIsZero = [];

        var preIndex = 0;
        for (let i = 0; i < inputCoins.length; i++){
            // commit each component of coin commitment
            randInputValue[i] = utils.RandInt();
            randInputSND[i] = utils.RandInt();
            randInputSNDIndexSK[i] = utils.RandInt();

            this.ComInputValue[i] = pc.PedCom.CommitAtIndex(inputCoins[i].CoinDetails.Value, randInputValue[i], constants.VALUE);
            this.ComInputSND[i] = pc.PedCom.CommitAtIndex(inputCoins[i].CoinDetails.SNDerivator, randInputSND[i], constants.SND);
            cmInputSNDIndexSK[i] = pc.PedCom.CommitAtIndex(inputCoins[i].CoinDetails.SNDerivator, randInputSNDIndexSK[i], constants.SK);

            cmInputValueAll = cmInputValueAll.Add(this.ComInputValue[i]);

            randInputValueAll.add(randInputValue[i]);
            randInputValueAll.umod(P256.n);

            /***** Build witness for proving one-out-of-N commitments is a commitment to the coins being spent *****/
            cmInputSum[i] = this.ComInputSK.add(this.ComInputValue[i]);
            cmInputSum[i] = cmInputSum[i].add(this.ComInputSND[i]);
            cmInputSum[i] = cmInputSum[i].add(this.ComInputShardID);

            randInputSum[i] = this.RandSK;
            randInputSum[i].add(randInputValue[i]);
            randInputSum[i].add(randInputSND[i]);
            randInputSum[i].add(randInputShardID);
            randInputSum[i].mod(P256.n);

            randInputSumAll.add(randInputSum[i]);
            randInputSumAll.umod(P256.n);

            // commitmentTemps is a list of commitments for protocol one-out-of-N
            commitmentTemps[i] = [];

            randInputIsZero[i] = inputCoins[i].CoinDetails.Randomness;
            randInputIsZero[i].Sub(randInputSum[i]);
            randInputIsZero[i].umod(P256.n);

            for (let j = 0; j < constants.CMRingSize; j++) {
                commitmentTemps[i][j] = commitments[preIndex+j].Sub(cmInputSum[i])
            }

            var indexIsZero = myCommitmentIndices[i] % constants.CMRingSize;

            this.OneOfManyWitness[i].set(commitmentTemps[i], commitmentIndices.slice(preIndex, preIndex+constants.CMRingSize), randInputIsZero[i], indexIsZero, constants.SK);
            preIndex = constants.CMRingSize * (i + 1);
            // ---------------------------------------------------

            /***** Build witness for proving that serial number is derived from the committed derivator *****/
            this.SerialNumberWitness[i].set(inputCoins[i].CoinDetails.SerialNumber, this.ComInputSK, this.ComInputSND[i],
                spendingKey, this.RandSK, inputCoins[i].CoinDetails.SNDerivator, randInputSND[i])
            // ---------------------------------------------------
        }

    }

    prove(hasPrivacy) {
        return new PaymentProof();
    }
}

class PaymentProof {
    constructor() {
        // for input coins
        this.OneOfManyProof = []; //[]*OneOutOfManyProof
        this.SerialNumberProof = []; // []*PKSNPrivacyProof
        // it is exits when tx has no privacy
        this.SNNoPrivacyProof = []; //[]*SNNoPrivacyProof

        // for output coins
        // for proving each value and sum of them are less than a threshold value
        this.ComOutputMultiRangeProof = new aggRange.AggregatedRangeProof();
        // for input = output
        // this.ComZeroProof = new zeroCom.ComZeroProof();
        this.InputCoins  = []; //[]*privacy.InputCoin
        this.OutputCoins = []; //[]*privacy.OutputCoin

        this.ComOutputValue = []; //   []*privacy.EllipticPoint
        this.ComOutputSND = []; //    []*privacy.EllipticPoint
        this.ComOutputShardID = []; // []*privacy.EllipticPoint

        this.ComInputSK     = P256.curve.point(0,0);
        this.ComInputValue = []; //  []*privacy.EllipticPoint
        this.ComInputSND  = []; //   []*privacy.EllipticPoint
        this.ComInputShardID = P256.curve.point(0,0);
    }

    toBytes() {
        return [];
    }
}

module.exports = {PaymentWitness, PaymentProof};

