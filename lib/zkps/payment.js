let BigInt = require('bn.js');
let ec = require('../ec');
let P256 = ec.P256;
let aggRange = require('./aggregatedrange');
let snNoPrivacy = require('./snnoprivacy');
let snPrivacy = require('./snprivacy');
let oneOfMany = require('./oneoutofmany');
let pc = require('../pedersen');
let constants = require('../constants');
let utils = require('../privacy_utils');
const bn = require('bn.js');
const common = require('../constantchain/common');


class PaymentWitness {
    constructor() {
        this.spendingKey = new BigInt(0);
        this.randSK = new BigInt(0);
        this.inputCoins = []; // []*privacy.InputCoin
        this.outputCoins = []; // []*privacy.OutputCoin
        this.commitmentIndices = []; // []*bigint
        this.myCommitmentIndices = []; // []uint64

        this.oneOfManyWitness = []; // []*OneOutOfManyWitness
        this.serialNumberWitness = []; // []*PKSNPrivacyWitness
        this.snNoPrivacyWitness = []; // []*snNoPrivacyWitness

        this.aggregatedRangeWitness = new aggRange.AggregatedRangeWitness();

        this.comOutputValue = []; // []*privacy.EllipticPoint
        this.comOutputSND = []; // []*privacy.EllipticPoint
        this.comOutputShardID = []; // []*privacy.EllipticPoint

        this.comInputSK = P256.curve.point(0, 0);
        this.comInputValue = []; // []*privacy.EllipticPoint
        this.comInputSND = []; // []*privacy.EllipticPoint
        this.comInputShardID = P256.curve.point(0, 0);
    }

    init(hasPrivacy, spendingKey, inputCoins, outputCoins, pkLastByteSender, commitments, commitmentIndices, myCommitmentIndices, fee) {
        let numInputCoin = inputCoins.length;

        if (!hasPrivacy) {
            for (let i = 0; i < outputCoins.length; i++) {
                outputCoins[i].Randomness = utils.randScalar();
                outputCoins[i].CoinDetails.commitAll();
            }
            this.spendingKey = spendingKey;
            this.inputCoins = inputCoins;
            this.outputCoins = outputCoins;

            let publicKey = inputCoins[0].CoinDetails.PublicKey;

            this.snNoPrivacyWitness = new Array(numInputCoin);
            for (let i = 0; i < inputCoins.length; i++) {
                /***** Build witness for proving that serial number is derived from the committed derivator *****/
                this.snNoPrivacyWitness[i] = new snNoPrivacy.SNNoPrivacyWitness();
                this.snNoPrivacyWitness[i].set(inputCoins[i].CoinDetails.SerialNumber, publicKey, inputCoins[i].CoinDetails.SNDerivator, this.spendingKey)
            }
            return null
        }

        this.spendingKey = spendingKey;
        this.inputCoins = inputCoins;
        this.outputCoins = outputCoins;
        this.commitmentIndices = commitmentIndices;
        this.myCommitmentIndices = myCommitmentIndices;

        // save rand SK for Schnorr signature
        this.randSK = utils.randScalar();
        // calculate sk commitment of input coins
        this.comInputSK = pc.PedCom.commitAtIndex(this.spendingKey, this.randSK, constants.SK);

        let randInputShardID = utils.randScalar();
        // calculate shard id commitment of input coins
        let shardID = common.getShardIDFromLastByte(pkLastByteSender);
        this.comInputShardID = pc.PedCom.commitAtIndex(new BigInt(shardID), randInputShardID, constants.SHARD_ID);


        this.comInputValue = new Array(numInputCoin);
        this.comInputSND = new Array(numInputCoin);

        let randInputValue = new Array(numInputCoin);
        let randInputSND = new Array(numInputCoin);

        // cmInputValueAll is sum of all input coins' value commitments
        let cmInputValueAll = P256.curve.point(0, 0);
        let randInputValueAll = new BigInt(0);

        // Summing all commitments of each input coin into one commitment and proving the knowledge of its Openings
        let cmInputSum = new Array(numInputCoin);
        let randInputSum = new Array(numInputCoin);

        // randInputSumAll is sum of all randomess of coin commitments
        let randInputSumAll = new BigInt(0);

        let commitmentTemps = new Array(numInputCoin);
        let randInputIsZero = new Array(numInputCoin);

        this.oneOfManyWitness = new Array(numInputCoin);
        this.serialNumberWitness = new Array(numInputCoin);

        let preIndex = 0;
        for (let i = 0; i < numInputCoin; i++) {
            // commit each component of coin commitment
            randInputValue[i] = utils.randScalar();
            randInputSND[i] = utils.randScalar();

            this.comInputValue[i] = pc.PedCom.commitAtIndex(inputCoins[i].CoinDetails.Value, randInputValue[i], constants.VALUE);
            this.comInputSND[i] = pc.PedCom.commitAtIndex(inputCoins[i].CoinDetails.SNDerivator, randInputSND[i], constants.SND);

            cmInputValueAll = cmInputValueAll.add(this.comInputValue[i]);

            randInputValueAll = randInputValueAll.add(randInputValue[i]);
            randInputValueAll = randInputValueAll.umod(P256.n);

            /***** Build witness for proving one-out-of-N commitments is a commitment to the coins being spent *****/
            cmInputSum[i] = this.comInputSK.add(this.comInputValue[i]);
            cmInputSum[i] = cmInputSum[i].add(this.comInputSND[i]);
            cmInputSum[i] = cmInputSum[i].add(this.comInputShardID);

            randInputSum[i] = this.randSK;
            randInputSum[i] = randInputSum[i].add(randInputValue[i]);
            randInputSum[i] = randInputSum[i].add(randInputSND[i]);
            randInputSum[i] = randInputSum[i].add(randInputShardID);
            randInputSum[i] = randInputSum[i].mod(P256.n);

            randInputSumAll = randInputSumAll.add(randInputSum[i]);
            randInputSumAll = randInputSumAll.umod(P256.n);

            // commitmentTemps is a list of commitments for protocol one-out-of-N
            commitmentTemps[i] = new Array(constants.CM_RING_SIZE);

            randInputIsZero[i] = inputCoins[i].CoinDetails.Randomness;
            randInputIsZero[i] = randInputIsZero[i].sub(randInputSum[i]);
            randInputIsZero[i] = randInputIsZero[i].umod(P256.n);

            for (let j = 0; j < constants.CM_RING_SIZE; j++) {
                commitmentTemps[i][j] = commitments[preIndex + j].sub(cmInputSum[i]);
            }

            let indexIsZero = myCommitmentIndices[i] % constants.CM_RING_SIZE;

            this.oneOfManyWitness[i] = new oneOfMany.OneOutOfManyWitness();
            this.oneOfManyWitness[i].set(commitmentTemps[i], randInputIsZero[i], indexIsZero);
            preIndex = constants.CM_RING_SIZE * (i + 1);
            // ---------------------------------------------------

            /***** Build witness for proving that serial number is derived from the committed derivator *****/
            this.serialNumberWitness[i] = new snPrivacy.SNPrivacyWitness();
            this.serialNumberWitness[i].set(inputCoins[i].CoinDetails.SerialNumber, this.comInputSK, this.comInputSND[i],
                spendingKey, this.randSK, inputCoins[i].CoinDetails.SNDerivator, randInputSND[i])

            // ---------------------------------------------------
        }

        let numOutputCoin = this.outputCoins.length;

        let randOutputValue = new Array(numOutputCoin);
        let randOutputSND = new Array(numOutputCoin);
        let randOutputShardID = new Array(numOutputCoin);
        let cmOutputValue = new Array(numOutputCoin);
        let cmOutputSND = new Array(numOutputCoin);
        let cmOutputShardID = new Array(numOutputCoin);

        let cmOutputSum = new Array(numOutputCoin);
        let randOutputSum = new Array(numOutputCoin);

        let cmOutputSumAll = P256.curve.point(0, 0);

        // cmOutputValueAll is sum of all value coin commitments
        let cmOutputValueAll = P256.curve.point(0, 0);
        let randOutputValueAll = new BigInt(0);

        console.log("Rand input value: ", randInputValueAll);

        for (let i = 0; i < numOutputCoin; i++) {
            if (i === numOutputCoin - 1) {
                randOutputValue[i] = randInputValueAll.sub(randOutputValueAll);
                randOutputValue[i] = randOutputValue[i].umod(P256.n);
            } else {
                randOutputValue[i] = utils.randScalar();
            }

            randOutputSND[i] = utils.randScalar();
            randOutputShardID[i] = utils.randScalar();

            cmOutputValue[i] = pc.PedCom.commitAtIndex(outputCoins[i].CoinDetails.Value, randOutputValue[i], constants.VALUE);
            cmOutputSND[i] = pc.PedCom.commitAtIndex(outputCoins[i].CoinDetails.SNDerivator, randOutputSND[i], constants.SND);

            let shardID = common.getShardIDFromLastByte(outputCoins[i].CoinDetails.getPubKeyLastByte());
            cmOutputShardID[i] = pc.PedCom.commitAtIndex(new BigInt(shardID), randOutputShardID[i], constants.SHARD_ID);


            randOutputSum[i] = randOutputValue[i].add(randOutputSND[i]);
            randOutputSum[i] = randOutputSum[i].add(randOutputShardID[i]);
            randOutputSum[i] = randOutputSum[i].umod(P256.n);

            cmOutputSum[i] = cmOutputValue[i].add(cmOutputSND[i]);
            cmOutputSum[i] = cmOutputSum[i].add(outputCoins[i].CoinDetails.PublicKey);
            cmOutputSum[i] = cmOutputSum[i].add(cmOutputShardID[i]);

            cmOutputValueAll = cmOutputValueAll.add(cmOutputValue[i]);
            randOutputValueAll = randOutputValueAll.add(randOutputValue[i]);
            randOutputValueAll = randOutputValueAll.umod(P256.n);
            // calculate final commitment for output coins
            outputCoins[i].CoinDetails.CoinCommitment = cmOutputSum[i];
            outputCoins[i].CoinDetails.Randomness = randOutputSum[i];

            cmOutputSumAll = cmOutputSumAll.add(cmOutputSum[i]);
        }

        // For aggregated range Protocol
        // proving each output value is less than vmax
        // proving sum of output values is less than vmax
        let outputValue = new Array(numOutputCoin);
        for (let i = 0; i < numOutputCoin; i++) {
            outputValue[i] = outputCoins[i].CoinDetails.Value;
        }
        this.aggregatedRangeWitness.set(outputValue, randOutputValue);
        // ---------------------------------------------------

        // save partial commitments (value, input, shardID)
        this.comOutputValue = cmOutputValue;
        this.comOutputSND = cmOutputSND;
        this.comOutputShardID = cmOutputShardID;

        console.log("Rand input value: ", randInputValueAll);
        console.log("Rand output value: ", randOutputValueAll);
        return null;
    }

    prove(hasPrivacy) {
        let proof = new PaymentProof();

        proof.commitmentIndices = this.commitmentIndices;

        proof.inputCoins = this.inputCoins;
        proof.outputCoins = this.outputCoins;
        proof.comOutputValue = this.comOutputValue;
        proof.comOutputSND = this.comOutputSND;
        proof.comOutputShardID = this.comOutputShardID;

        proof.comInputSK = this.comInputSK;
        proof.comInputValue = this.comInputValue;
        proof.comInputSND = this.comInputSND;
        proof.comInputShardID = this.comInputShardID;

        let numInputCoins = this.inputCoins.length;

        // if hasPrivacy == false, don't need to create the zero knowledge proof
        // proving user has spending key corresponding with public key in input coins
        // is proved by signing with spending key
        if (!hasPrivacy) {
            // Proving that serial number is derived from the committed derivator
            proof.snNoPrivacyProof = new Array(numInputCoins);

            for (let i = 0; i < numInputCoins; i++) {
                proof.snNoPrivacyProof[i] = this.snNoPrivacyWitness[i].prove();
            }
            return proof;
        }

        // if hasPrivacy == true
        proof.oneOfManyProof = new Array(numInputCoins);
        proof.serialNumberProof = new Array(numInputCoins);

        for (let i = 0; i < numInputCoins; i++) {
            // Proving one-out-of-N commitments is a commitment to the coins being spent
            let oneOfMany = this.oneOfManyWitness[i].prove();
            if (oneOfMany.err === null){
                proof.oneOfManyProof[i] = oneOfMany.proof;
            }

            // Proving that serial number is derived from the committed derivator
            proof.serialNumberProof[i] = this.serialNumberWitness[i].prove();
        }

        // Proving that each output values and sum of them does not exceed v_max
        proof.aggregatedRangeProof = this.aggregatedRangeWitness.prove();

        return proof;
    }
}


class PaymentProof {
    constructor() {
        // for input coins
        this.oneOfManyProof = []; //[]*OneOutOfManyProof
        this.serialNumberProof = []; // []*PKSNPrivacyProof
        // it is exits when tx has no privacy
        this.snNoPrivacyProof = []; //[]*snNoPrivacyProof

        // for output coins
        // for proving each value and sum of them are less than a threshold value
        this.aggregatedRangeProof = new aggRange.AggregatedRangeProof();

        this.inputCoins = []; //[]*privacy.InputCoin
        this.outputCoins = []; //[]*privacy.OutputCoin

        this.comOutputValue = []; //   []*privacy.EllipticPoint
        this.comOutputSND = []; //    []*privacy.EllipticPoint
        this.comOutputShardID = []; // []*privacy.EllipticPoint

        this.comInputSK = P256.curve.point(0, 0);
        this.comInputValue = []; //  []*privacy.EllipticPoint
        this.comInputSND = []; //   []*privacy.EllipticPoint
        this.comInputShardID = P256.curve.point(0, 0);

        this.commitmentIndices = []; // big int array
    }

    toBytes() {
        let hasPrivacy = this.oneOfManyProof.length > 0;
        let paymentProofSize = 0;

        let partialBytes = new Array(constants.NUM_PROOF_PROPERTIES);

        // OneOfManyProof
        let oneOfManyArrLen = this.oneOfManyProof.length;
        partialBytes[0] = new Uint8Array(1 + 2 * oneOfManyArrLen + oneOfManyArrLen * constants.ONE_OF_MANY_PROOF_SIZE);
        partialBytes[0].set([oneOfManyArrLen], 0);
        let offset = 1;
        for (let i = 0; i < oneOfManyArrLen; i++) {
            partialBytes[0].set(utils.intToByteArr(constants.ONE_OF_MANY_PROOF_SIZE), offset);
            offset += 2;
            partialBytes[0].set(this.oneOfManyProof[i].toBytes(), offset);
            offset += constants.ONE_OF_MANY_PROOF_SIZE;
        }
        paymentProofSize += partialBytes[0].length;

        // SerialNumberProofSize
        let serialNumberArrLen = this.serialNumberProof.length;
        partialBytes[1] = new Uint8Array(1 + 2 * serialNumberArrLen + serialNumberArrLen * constants.SN_PRIVACY_PROOF_SIZE);
        partialBytes[1].set([serialNumberArrLen], 0);
        offset = 1;
        for (let i = 0; i < serialNumberArrLen; i++) {
            partialBytes[1].set(utils.intToByteArr(constants.SN_PRIVACY_PROOF_SIZE), offset);
            offset += 2;
            partialBytes[1].set(this.serialNumberProof[i].toBytes(), offset);
            offset += constants.SN_PRIVACY_PROOF_SIZE;
        }
        paymentProofSize += partialBytes[1].length;

        // SerialNumber NoPrivacy ProofSize
        let snNoPrivacyArrLen = this.snNoPrivacyProof.length;
        partialBytes[2] = new Uint8Array(1 + snNoPrivacyArrLen + snNoPrivacyArrLen * constants.SN_PRIVACY_PROOF_SIZE);
        partialBytes[2].set([snNoPrivacyArrLen], 0);
        offset = 1;
        for (let i = 0; i < snNoPrivacyArrLen; i++) {
            partialBytes[2].set([constants.SN_NO_PRIVACY_PROOF_SIZE], offset);
            offset += 1;
            partialBytes[2].set(this.snNoPrivacyProof[i].toBytes(), offset);
            offset += constants.SN_NO_PRIVACY_PROOF_SIZE;
        }
        paymentProofSize += partialBytes[2].length;

        // ComOutputMultiRangeProofSize
        if (hasPrivacy) {
            let comOutputMultiRangeProof = this.aggregatedRangeProof.toBytes();
            partialBytes[3] = new Uint8Array(2 + comOutputMultiRangeProof.length);
            partialBytes[3].set(utils.intToByteArr(comOutputMultiRangeProof.length), 0);
            partialBytes[3].set(comOutputMultiRangeProof, 2);
        } else {
            partialBytes[3] = new Uint8Array(2);
            partialBytes[3].set([0, 0], 0);
        }
        paymentProofSize += partialBytes[3].length;

        // InputCoins
        let inputCoinArrLen = this.inputCoins.length;
        let inputCoinBytesTmp = new Array(inputCoinArrLen);
        let inputCoinBytesSize = 0;
        for (let i = 0; i < inputCoinArrLen; i++) {
            inputCoinBytesTmp[i] = this.inputCoins[i].toBytes();
            inputCoinBytesSize += inputCoinBytesTmp[i].length;
        }

        partialBytes[4] = new Uint8Array(1 + inputCoinArrLen + inputCoinBytesSize);
        partialBytes[4].set([inputCoinArrLen], 0);
        offset = 1;
        for (let i = 0; i < inputCoinArrLen; i++) {
            partialBytes[4].set([inputCoinBytesTmp[i].length], offset);
            offset += 1;
            partialBytes[4].set(inputCoinBytesTmp[i], offset);
            offset += inputCoinBytesTmp[i].length;
        }
        paymentProofSize += partialBytes[4].length;

        // OutputCoins
        let outputCoinArr = this.outputCoins.length;
        let outputCoinBytesTmp = new Array(outputCoinArr);
        let outputCoinBytesSize = 0;
        for (let i = 0; i < outputCoinArr; i++) {
            outputCoinBytesTmp[i] = this.outputCoins[i].toBytes();
            outputCoinBytesSize += outputCoinBytesTmp[i].length;
        }

        partialBytes[5] = new Uint8Array(1 + outputCoinArr + outputCoinBytesSize);
        partialBytes[5].set([outputCoinArr], 0);
        offset = 1;
        for (let i = 0; i < outputCoinArr; i++) {
            partialBytes[5].set([outputCoinBytesTmp[i].length], offset);
            offset += 1;
            partialBytes[5].set(outputCoinBytesTmp[i], offset);
            offset += outputCoinBytesTmp[i].length;
        }
        paymentProofSize += partialBytes[5].length;

        // ComOutputValue
        let comOutputValueArrLen = this.comOutputValue.length;
        partialBytes[6] = new Uint8Array(1 + comOutputValueArrLen + comOutputValueArrLen * constants.COMPRESS_POINT_SIZE);
        partialBytes[6].set([comOutputValueArrLen], 0);
        offset = 1;
        for (let i = 0; i < comOutputValueArrLen; i++) {
            partialBytes[6].set([constants.COMPRESS_POINT_SIZE], offset);
            offset += 1;
            partialBytes[6].set(this.comOutputValue[i].compress(), offset);
            offset += constants.COMPRESS_POINT_SIZE;
        }
        paymentProofSize += partialBytes[6].length;

        // ComOutputSND
        let comOutputSNDArr = this.comOutputSND.length;
        partialBytes[7] = new Uint8Array(1 + comOutputSNDArr + comOutputSNDArr * constants.COMPRESS_POINT_SIZE);
        partialBytes[7].set([comOutputSNDArr], 0);
        offset = 1;
        for (let i = 0; i < comOutputSNDArr; i++) {
            partialBytes[7].set([constants.COMPRESS_POINT_SIZE], offset);
            offset += 1;
            partialBytes[7].set(this.comOutputSND[i].compress(), offset);
            offset += constants.COMPRESS_POINT_SIZE;
        }
        paymentProofSize += partialBytes[7].length;

        // ComOutputShardID
        let comOutputShardIDArrLen = this.comOutputShardID.length;
        partialBytes[8] = new Uint8Array(1 + comOutputShardIDArrLen + comOutputShardIDArrLen * constants.COMPRESS_POINT_SIZE);
        partialBytes[8].set([comOutputShardIDArrLen], 0);
        offset = 1;
        for (let i = 0; i < comOutputShardIDArrLen; i++) {
            partialBytes[8].set([constants.COMPRESS_POINT_SIZE], offset);
            offset += 1;
            partialBytes[8].set(this.comOutputShardID[i].compress(), offset);
            offset += constants.COMPRESS_POINT_SIZE;
        }
        paymentProofSize += partialBytes[8].length;

        // ComInputSK
        if (this.comInputSK !== null) {
            partialBytes[9] = new Uint8Array(1 + constants.COMPRESS_POINT_SIZE);
            partialBytes[9].set([constants.COMPRESS_POINT_SIZE], 0);
            partialBytes[9].set(this.comInputSK.compress(), 1);
        } else {
            partialBytes[9] = new Uint8Array(1);
            partialBytes[9].set([0], 0);
        }
        paymentProofSize += partialBytes[9].length;

        // ComInputValue
        let comInputValueArrLen = this.comInputValue.length;
        partialBytes[10] = new Uint8Array(1 + comInputValueArrLen + comInputValueArrLen * constants.COMPRESS_POINT_SIZE);
        partialBytes[10].set([comInputValueArrLen], 0);
        offset = 1;
        for (let i = 0; i < comInputValueArrLen; i++) {
            partialBytes[10].set([constants.COMPRESS_POINT_SIZE], offset);
            offset += 1;
            partialBytes[10].set(this.comInputValue[i].compress(), offset);
            offset += constants.COMPRESS_POINT_SIZE;
        }
        paymentProofSize += partialBytes[10].length;

        // ComInputSND
        let comInputSNDArrLen = this.comInputSND.length;
        partialBytes[11] = new Uint8Array(1 + comInputSNDArrLen + comInputSNDArrLen * constants.COMPRESS_POINT_SIZE);
        partialBytes[11].set([comInputSNDArrLen], 0);
        offset = 1;
        for (let i = 0; i < comInputSNDArrLen; i++) {
            partialBytes[11].set([constants.COMPRESS_POINT_SIZE], offset);
            offset += 1;
            partialBytes[11].set(this.comInputSND[i].compress(), offset);
            offset += constants.COMPRESS_POINT_SIZE;
        }
        paymentProofSize += partialBytes[11].length;

        // ComInputShardID
        if (this.comInputShardID !== null) {
            partialBytes[12] = new Uint8Array(1 + constants.COMPRESS_POINT_SIZE);
            partialBytes[12].set([constants.COMPRESS_POINT_SIZE], 0);
            partialBytes[12].set(this.comInputShardID.compress(), 1);
        } else {
            partialBytes[12] = new Uint8Array(1);
            partialBytes[12].set([0], 0);
        }
        paymentProofSize += partialBytes[12].length;

        // convert commitment index to bytes array
        partialBytes[13] = new Uint8Array(this.commitmentIndices.length * constants.UINT64_SIZE);
        offset = 0;
        for (let i = 0; i < this.commitmentIndices.length; i++) {
            partialBytes[13].set(utils.addPaddingBigInt(new bn.BN(this.commitmentIndices[i]), constants.UINT64_SIZE), offset);
            offset += constants.UINT64_SIZE;
        }
        paymentProofSize += partialBytes[13].length;

        let bytes = new Uint8Array(paymentProofSize);
        let index = 0;
        for (let i = 0; i < constants.NUM_PROOF_PROPERTIES; i++) {
            bytes.set(partialBytes[i], index);
            index += partialBytes[i].length;
        }

        console.log("Proof size: ", bytes.length);
        console.log("Proof: ", [...bytes].join(', '));

        return bytes;
    }
}

// function

module.exports = {
    PaymentWitness,
    PaymentProof
};