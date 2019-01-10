let common = require('../common');
let ec = require('../ec');
let P256 = ec.P256;
let aggRange = require('./aggregatedrange');
let zeroCom = require('./zerocommitment');
let snnoprivacy = require('./snnoprivacy');
let oneofmany = require('./oneoutofmany');
let pc = require('../pedersen');
let constants = require('../constants');
let utils = require('../privacy_utils');


class PaymentWitness {
    constructor() {
        this.spendingKey = new common.BigInt(0);
        this.randSK = new common.BigInt(0);
        this.inputCoins = [];               // []*privacy.InputCoin
        this.outputCoins = [];              // []*privacy.OutputCoin
        this.commitmentIndices = [];        // []uint64
        this.myCommitmentIndices = [];      // []uint64

        this.oneOfManyWitness = [];         // []*OneOutOfManyWitness
        this.serialNumberWitness = [];      // []*PKSNPrivacyWitness
        this.snNoPrivacyWitness = [];       // []*snNoPrivacyWitness

        this.aggregatedRangeWitness = new aggRange.AggregatedRangeWitness();
        this.comZeroWitness = new zeroCom.ComZeroWitness();

        this.comOutputValue = [];           // []*privacy.EllipticPoint
        this.comOutputSND = [];             // []*privacy.EllipticPoint
        this.comOutputShardID = [];         // []*privacy.EllipticPoint

        this.comInputSK = P256.curve.point(0, 0);
        this.comInputValue = [];            // []*privacy.EllipticPoint
        this.comInputSND = [];              // []*privacy.EllipticPoint
        this.comInputShardID = P256.curve.point(0, 0);
    }

    init(hasPrivacy, spendingKey, inputCoins, outputCoins, pkLastByteSender, commitments, commitmentIndices, myCommitmentIndices, fee) {
        if (!hasPrivacy) {
            for (let i = 0; i < outputCoins.length; i++) {
                outputCoins[i].Randomness = utils.RandInt();
                outputCoins[i].CoinDetails.commitAll();
            }
            this.spendingKey = spendingKey;
            this.inputCoins = inputCoins;
            this.outputCoins = outputCoins;

            let publicKey = inputCoins[0].CoinDetails.PublicKey;

            for (let i = 0; i < inputCoins.length; i++) {
                /***** Build witness for proving that serial number is derived from the committed derivator *****/
                this.snNoPrivacyWitness[i] = new snnoprivacy.SNNoPrivacyWitness();
                this.snNoPrivacyWitness[i].set(inputCoins[i].CoinDetails.SerialNumber, publicKey, inputCoins[i].CoinDetails.SNDerivator, this.spendingKey)
            }
            return null
        }
        this.spendingKey = spendingKey;
        this.inputCoins = inputCoins;
        this.outputCoins = outputCoins;
        this.commitmentIndices = commitmentIndices;
        this.myCommitmentIndices = myCommitmentIndices;

        let numInputCoin = this.inputCoins.length;

        // save rand SK for Schnorr signature
        this.randSK = utils.RandInt();
        // calculate sk commitment of input coins
        this.comInputSK = pc.PedCom.CommitAtIndex(this.spendingKey, this.randSK, constants.SK);

        let randInputShardID = utils.RandInt();
        // calculate shard id commitment of input coins
        this.comInputShardID = pc.PedCom.CommitAtIndex(new common.BigInt(pkLastByteSender), randInputShardID, constants.SHARDID);

        let randInputValue = [];
        let randInputSND = [];
        let randInputSNDIndexSK = [];
        // It is used for proving 2 commitments commit to the same value (input)
        let cmInputSNDIndexSK = [];

        // cmInputValueAll is sum of all input coins' value commitments
        let cmInputValueAll = P256.curve.point(0, 0);
        let randInputValueAll = new common.BigInt(0);

        // Summing all commitments of each input coin into one commitment and proving the knowledge of its Openings
        let cmInputSum = [];
        let randInputSum = [];

        // randInputSumAll is sum of all randomess of coin commitments
        let randInputSumAll = new common.BigInt(0);

        let commitmentTemps = new Array(numInputCoin);
        let randInputIsZero = new Array(numInputCoin);

        let preIndex = 0;
        for (let i = 0; i < numInputCoin; i++) {
            // commit each component of coin commitment
            randInputValue[i] = utils.RandInt();
            randInputSND[i] = utils.RandInt();
            randInputSNDIndexSK[i] = utils.RandInt();

            this.comInputValue[i] = pc.PedCom.CommitAtIndex(inputCoins[i].CoinDetails.Value, randInputValue[i], constants.VALUE);
            this.comInputSND[i] = pc.PedCom.CommitAtIndex(inputCoins[i].CoinDetails.SNDerivator, randInputSND[i], constants.SND);
            cmInputSNDIndexSK[i] = pc.PedCom.CommitAtIndex(inputCoins[i].CoinDetails.SNDerivator, randInputSNDIndexSK[i], constants.SK);

            cmInputValueAll = cmInputValueAll.add(this.comInputValue[i]);

            randInputValueAll.add(randInputValue[i]);
            randInputValueAll.umod(P256.n);

            /***** Build witness for proving one-out-of-N commitments is a commitment to the coins being spent *****/
            cmInputSum[i] = this.comInputSK.add(this.comInputValue[i]);
            cmInputSum[i] = cmInputSum[i].add(this.comInputSND[i]);
            cmInputSum[i] = cmInputSum[i].add(this.comInputShardID);

            randInputSum[i] = this.randSK;
            randInputSum[i].add(randInputValue[i]);
            randInputSum[i].add(randInputSND[i]);
            randInputSum[i].add(randInputShardID);
            randInputSum[i].mod(P256.n);

            randInputSumAll.add(randInputSum[i]);
            randInputSumAll.umod(P256.n);

            // commitmentTemps is a list of commitments for protocol one-out-of-N
            commitmentTemps[i] = new Array(constants.CMRingSize);

            randInputIsZero[i] = inputCoins[i].CoinDetails.Randomness;
            randInputIsZero[i].sub(randInputSum[i]);
            randInputIsZero[i].umod(P256.n);

            for (let j = 0; j < constants.CMRingSize; j++) {
                commitmentTemps[i][j] = commitments[preIndex + j].add(cmInputSum[i].inverse());
            }

            let indexIsZero = myCommitmentIndices[i] % constants.CMRingSize;

            this.oneOfManyWitness[i] = new oneofmany.OneOutOfManyWitness();
            this.oneOfManyWitness[i].set(commitmentTemps[i], commitmentIndices.slice(preIndex, preIndex + constants.CMRingSize), randInputIsZero[i], indexIsZero, constants.SK);
            preIndex = constants.CMRingSize * (i + 1);
            // ---------------------------------------------------

            /***** Build witness for proving that serial number is derived from the committed derivator *****/
            // this.serialNumberWitness[i].set(inputCoins[i].CoinDetails.SerialNumber, this.comInputSK, this.comInputSND[i],
            //     spendingKey, this.randSK, inputCoins[i].CoinDetails.SNDerivator, randInputSND[i])
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
        let randOutputValueAll = new common.BigInt(0);

        for (let i = 0; i < numOutputCoin; i++) {
            randOutputValue[i] = utils.RandInt();
            randOutputSND[i] = utils.RandInt();
            randOutputShardID[i] = utils.RandInt();

            cmOutputValue[i] = pc.PedCom.CommitAtIndex(outputCoins[i].CoinDetails.Value, randOutputValue[i], constants.VALUE);
            cmOutputSND[i] = pc.PedCom.CommitAtIndex(outputCoins[i].CoinDetails.SNDerivator, randOutputSND[i], constants.SND);
            cmOutputShardID[i] = pc.PedCom.CommitAtIndex(new common.BigInt(outputCoins[i].CoinDetails.getPubKeyLastByte()), randOutputShardID[i], constants.SHARDID);

            randOutputSum[i] = randOutputValue[i];
            randOutputSum[i].add(randOutputSND[i]);
            randOutputSum[i].add(randOutputShardID[i]);
            randOutputSum[i].umod(P256.n);

            cmOutputSum[i] = cmOutputValue[i];
            cmOutputSum[i] = cmOutputSum[i].add(cmOutputSND[i]);
            cmOutputSum[i] = cmOutputSum[i].add(outputCoins[i].CoinDetails.PublicKey);
            cmOutputSum[i] = cmOutputSum[i].add(cmOutputShardID[i]);

            cmOutputValueAll = cmOutputValueAll.add(cmOutputValue[i]);
            randOutputValueAll.add(randOutputValue[i]);

            // calculate final commitment for output coins
            outputCoins[i].CoinDetails.CoinCommitment = cmOutputSum[i];
            outputCoins[i].CoinDetails.Randomness = randOutputSum[i];

            cmOutputSumAll = cmOutputSumAll.add(cmOutputSum[i]);
        }

        // For Multi Range Protocol
        // proving each output value is less than vmax
        // proving sum of output values is less than vmax
        let outputValue = new Array(numOutputCoin);
        for (let i = 0; i < numOutputCoin; i++) {
            outputValue[i] = outputCoins[i].CoinDetails.Value;
        }
        this.aggregatedRangeWitness.set(outputValue, constants.MaxEXP);
        // ---------------------------------------------------

        // Build witness for proving Sum(Input's value) == Sum(Output's Value)
        if (fee > 0) {
            cmOutputValueAll = cmOutputValueAll.add(pc.PedCom.G[constants.VALUE].mul(new common.BigInt(fee)));
        }

        //cmEqualCoinValue := new(privacy.EllipticPoint)
        let cmEqualCoinValue = cmInputValueAll.add(cmOutputValueAll.inverse());

        let randEqualCoinValue = randInputValueAll;
        randEqualCoinValue.sub(randOutputValueAll);
        randEqualCoinValue.umod(P256.n);

        this.comZeroWitness = new zeroCom.ComZeroWitness();
        this.comZeroWitness.set(cmEqualCoinValue, constants.VALUE, randEqualCoinValue);
        // ---------------------------------------------------

        // save partial commitments (value, input, shardID)
        this.comOutputValue = cmOutputValue;
        this.comOutputSND = cmOutputSND;
        this.comOutputShardID = cmOutputShardID;
        return null;
    }

    prove(hasPrivacy) {

        let proof = new PaymentProof();

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
        proof.serialNumberProof = new Array(numInputCoins);
        proof.serialNumberProof = new Array(numInputCoins);

        for (let i = 0; i < numInputCoins; i++) {
            // Proving one-out-of-N commitments is a commitment to the coins being spent
            proof.oneOfManyProof[i] = this.oneOfManyWitness[i].prove();

            // Proving that serial number is derived from the committed derivator
            proof.serialNumberProof[i] = this.serialNumberWitness[i].prove();
        }

        // Proving that each output values and sum of them does not exceed v_max
        proof.aggregatedRangeProof = this.aggregatedRangeWitness[i].prove();

        // Proving that sum of all input values is equal to sum of all output values
        proof.ComZeroProof = this.comZeroWitness.prove();

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
        // for input = output
        // this.ComZeroProof = new zeroCom.ComZeroProof();
        this.inputCoins = []; //[]*privacy.InputCoin
        this.outputCoins = []; //[]*privacy.OutputCoin

        this.comOutputValue = []; //   []*privacy.EllipticPoint
        this.comOutputSND = []; //    []*privacy.EllipticPoint
        this.comOutputShardID = []; // []*privacy.EllipticPoint

        this.comInputSK = P256.curve.point(0, 0);
        this.comInputValue = []; //  []*privacy.EllipticPoint
        this.comInputSND = []; //   []*privacy.EllipticPoint
        this.comInputShardID = P256.curve.point(0, 0);
    }

    toBytes() {
        let proofbytes = [];
        let hasPrivacy = this.oneOfManyProof.length > 0;
        if (hasPrivacy){
            proofbytes = new Uint8Array();
        }
        // OneOfManyProofSize
        proofbytes = append(proofbytes, byte(len(paymentProof.OneOfManyProof)))
        for i := 0; i < len(paymentProof.OneOfManyProof); i++ {
            oneOfManyProof := paymentProof.OneOfManyProof[i].Bytes()
            proofbytes = append(proofbytes, privacy.IntToByteArr(privacy.OneOfManyProofSize)...)
            proofbytes = append(proofbytes, oneOfManyProof...)
        }

        // SerialNumberProofSize
        proofbytes = append(proofbytes, byte(len(paymentProof.SerialNumberProof)))
        for i := 0; i < len(paymentProof.SerialNumberProof); i++ {
            serialNumberProof := paymentProof.SerialNumberProof[i].Bytes()
            proofbytes = append(proofbytes, privacy.IntToByteArr(privacy.SNPrivacyProofSize)...)
            proofbytes = append(proofbytes, serialNumberProof...)
        }

        // SNNoPrivacyProofSize
        proofbytes = append(proofbytes, byte(len(paymentProof.SNNoPrivacyProof)))
        for i := 0; i < len(paymentProof.SNNoPrivacyProof); i++ {
            snNoPrivacyProof := paymentProof.SNNoPrivacyProof[i].Bytes()
            proofbytes = append(proofbytes, byte(privacy.SNNoPrivacyProofSize))
            proofbytes = append(proofbytes, snNoPrivacyProof...)
        }

        // ComOutputMultiRangeProofSize
        if hasPrivacy {
            comOutputMultiRangeProof := paymentProof.ComOutputMultiRangeProof.Bytes()
            proofbytes = append(proofbytes, privacy.IntToByteArr(len(comOutputMultiRangeProof))...)
            proofbytes = append(proofbytes, comOutputMultiRangeProof...)
        } else {
            proofbytes = append(proofbytes, []byte{0, 0}...)
        }

        if hasPrivacy {
            comZeroProof := paymentProof.ComZeroProof.Bytes()
            proofbytes = append(proofbytes, byte(len(comZeroProof)))
            proofbytes = append(proofbytes, comZeroProof...)
        } else {
            proofbytes = append(proofbytes, byte(0))
        }

        // InputCoins
        proofbytes = append(proofbytes, byte(len(paymentProof.InputCoins)))

        for i := 0; i < len(paymentProof.InputCoins); i++ {
            inputCoins := paymentProof.InputCoins[i].Bytes()
            proofbytes = append(proofbytes, byte(len(inputCoins)))
            proofbytes = append(proofbytes, inputCoins...)
        }
        // OutputCoins
        proofbytes = append(proofbytes, byte(len(paymentProof.OutputCoins)))
        for i := 0; i < len(paymentProof.OutputCoins); i++ {
            outputCoins := paymentProof.OutputCoins[i].Bytes()
            lenOutputCoins := len(outputCoins)
            proofbytes = append(proofbytes, byte(lenOutputCoins))
            proofbytes = append(proofbytes, outputCoins...)
        }
        // ComOutputValue
        proofbytes = append(proofbytes, byte(len(paymentProof.ComOutputValue)))
        for i := 0; i < len(paymentProof.ComOutputValue); i++ {
            comOutputValue := paymentProof.ComOutputValue[i].Compress()
            proofbytes = append(proofbytes, byte(privacy.CompressedPointSize))
            proofbytes = append(proofbytes, comOutputValue...)
        }
        // ComOutputSND
        proofbytes = append(proofbytes, byte(len(paymentProof.ComOutputSND)))
        for i := 0; i < len(paymentProof.ComOutputSND); i++ {
            comOutputSND := paymentProof.ComOutputSND[i].Compress()
            proofbytes = append(proofbytes, byte(privacy.CompressedPointSize))
            proofbytes = append(proofbytes, comOutputSND...)
        }
        // ComOutputShardID
        proofbytes = append(proofbytes, byte(len(paymentProof.ComOutputShardID)))
        for i := 0; i < len(paymentProof.ComOutputShardID); i++ {
            comOutputShardID := paymentProof.ComOutputShardID[i].Compress()
            proofbytes = append(proofbytes, byte(privacy.CompressedPointSize))
            proofbytes = append(proofbytes, comOutputShardID...)
        }

        //ComInputSK 				*privacy.EllipticPoint
        if paymentProof.ComInputSK != nil {
            comInputSK := paymentProof.ComInputSK.Compress()
            proofbytes = append(proofbytes, byte(privacy.CompressedPointSize))
            proofbytes = append(proofbytes, comInputSK...)
        } else {
            proofbytes = append(proofbytes, byte(0))
        }
        //ComInputValue 		[]*privacy.EllipticPoint
        proofbytes = append(proofbytes, byte(len(paymentProof.ComInputValue)))
        for i := 0; i < len(paymentProof.ComInputValue); i++ {
            comInputValue := paymentProof.ComInputValue[i].Compress()
            proofbytes = append(proofbytes, byte(privacy.CompressedPointSize))
            proofbytes = append(proofbytes, comInputValue...)
        }
        //ComInputSND 			[]*privacy.EllipticPoint
        proofbytes = append(proofbytes, byte(len(paymentProof.ComInputSND)))
        for i := 0; i < len(paymentProof.ComInputSND); i++ {
            comInputSND := paymentProof.ComInputSND[i].Compress()
            proofbytes = append(proofbytes, byte(privacy.CompressedPointSize))
            proofbytes = append(proofbytes, comInputSND...)
        }
        //ComInputShardID 	*privacy.EllipticPoint
        if paymentProof.ComInputShardID != nil {
            comInputShardID := paymentProof.ComInputShardID.Compress()
            proofbytes = append(proofbytes, byte(privacy.CompressedPointSize))
            proofbytes = append(proofbytes, comInputShardID...)
        } else {
            proofbytes = append(proofbytes, byte(0))
        }
        return [];
    }
}

module.exports = {PaymentWitness, PaymentProof};

