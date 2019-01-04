var common = require('./../common');
var ec = require('./../ec.js');
var constants = require('./../constants');
var key = require('./../key');
var utils = require('./../privacy_utils');
var zkp = require('./../zkps/zkp');
var coin = require('./../coin');

const TxVersion = 1;
const ConstantID = new Uint8Array(32);
ConstantID[0] = 4;

const TxNormalType = 'n';

function RandomCommitmentsProcess(inputCoins, CMRingSize, db, chainID, tokenID) {
    //todo
    return {
        commitmentIndices: new BigUint64Array(),
        myCommitmentIndices: new BigUint64Array(),
    }
}

class Tx {
    constructor() {
        this.Version = 0;
        this.Type = '';
        this.LockTime = 0;
        this.Fee = 0;

        this.SigPubKey = new Uint8Array(0);
        this.Sig = new Uint8Array(0);
        this.Proof = new zkp.PaymentProof();

        this.PubKeyLastByteSender = 0x00;
        this.Metadata = new Uint8Array(0);

        this.sigPrivKey = new Uint8Array(0);
    }

    init(senderSK, paymentInfo, inputCoins, fee, hasPrivacy, db, tokenID, metaData) {
        // set version tx
        this.Version = TxVersion;

        // set tokenID for constant
        if (tokenID.length === 0) {
            tokenID = ConstantID;
        }

        // set lock time
        if (this.LockTime === 0) {
            this.LockTime = new Date().getTime();
        }

        // generate sender's key set from senderSK
        var senderKeySet = key.KeySet(senderSK);

        // get public key's last byte of sender
        var senderPK = senderKeySet.PaymentAddress.PublicKey;
        var pkLastByteSender = senderPK[senderPK.length - 1];

        //set meta data
        this.Metadata = metaData;

        // check whether tx is custom token tx or not
        if (inputCoins.length === 0 && fee === 0 && !hasPrivacy) {
            console.log("CREATE TX CUSTOM TOKEN");
            this.Fee = fee;
            this.sigPrivKey = senderSK;
            this.PubKeyLastByteSender = pkLastByteSender;

            this.sign(hasPrivacy);
        }

        // set type tx
        this.Type = TxNormalType;

        // set chain id
        //todo:
        var chainID = pkLastByteSender;

        // get commitment list from db for proving
        // todo:
        // call api to random commitments list
        var randCommitments = RandomCommitmentsProcess(inputCoins, privacy.CMRingSize, db, chainID, tokenID);
        var commitmentIndexs = randCommitments.commitmentIndices;   // array index random of commitments in db
        var myCommitmentIndexs = randCommitments.myCommitmentIndices;  // index in array index random of commitment in db

        // Check number of list of random commitments, list of random commitment indices
        if (commitmentIndexs.length !== inputCoins.length * constants.CMRingSize) {
            return new Error("Invalid random commitments");
        }

        if (myCommitmentIndexs.length !== inputCoins.length) {
            return new Error("Number of list my commitment indices must be equal to number of input coins");
        }

        // Calculate sum of all output coins' value
        var sumOutputValue = new common.BigInt(0);
        for (var i = 0; i < paymentInfo.length; i++) {
            sumOutputValue = sumOutputValue.add(paymentInfo.Amount);
        }

        // Calculate sum of all input coins' value
        var sumInputValue = new common.BigInt(0);
        for (var i = 0; i < inputCoins.length; i++) {
            sumInputValue = sumInputValue.add(inputCoins.CoinDetails.Value);
        }

        // Calculate over balance, it will be returned to sender
        var overBalance = sumInputValue.sub(sumOutputValue);
        overBalance = overBalance.sub(fee);

        if (overBalance.lt(0)) {
            return new Error("Input value less than output value");
        }

        // if overBalance > 0, create a new payment info with pk is sender's pk and amount is overBalance
        if (overBalance.gt(0)) {
            var changePaymentInfo = new key.PaymentInfo;
            changePaymentInfo.Amount = overBalance;
            changePaymentInfo.PaymentAddress = senderKeySet.PaymentAddress;
            paymentInfo.push(changePaymentInfo);
        }

        // create new output coins
        var outputCoins = [];

        // generates SNDs for output coins
        var ok = true;
        var sndOuts = [];
        while (ok) {
            var sndOut = new common.BigInt(0);
            for (i = 0; i < paymentInfo.length; i++) {
                sndOut = utils.RandInt(constants.BigIntSize);
                while (true) {
                    //todo:
                    // call api to check SND existence
                    // var ok1 = CheckSNDerivatorExistence(tokenID, sndOut, chainID, db)
                    var ok1 = false;

                    // if sndOut existed, then re-random it
                    if (ok1) {
                        sndOut = utils.RandInt(constants.BigIntSize);
                    } else {
                        break
                    }
                }
                sndOuts.push(sndOut);
            }
            // if sndOuts has two elements that have same value, then re-generates it
            ok = utils.checkDuplicateBigIntArray(sndOuts);
            if (ok) {
                sndOuts = [];
            }
        }

        // create new output coins with info: Pk, value, last byte of pk, snd
        for (i = 0; i < paymentInfo.length; i++) {
            outputCoins[i] = new coin.OutputCoin();
            outputCoins[i].CoinDetails.Value = paymentInfo[i].Amount;
            outputCoins[i].CoinDetails.PublicKey = ec.P256.decompress(paymentInfo[i].PaymentAddress.PublicKey);
            outputCoins[i].CoinDetails.SNDerivator = sndOuts[i];
        }

        // assign fee tx
        this.Fee = fee;

        // create zero knowledge proof of payment
        this.Proof = new zkp.PaymentProof();

        // get list of commitments for proving one-out-of-many from commitmentIndexs
        var commitmentProving = [];
        for (i = 0; i< commitmentIndexs.length; i++) {
            commitmentProving[i] = new ec.P256.point();
            //Todo:
            // call api to get commitment by index
            // var temp = db.GetCommitmentByIndex(tokenID, cmIndex, chainID)
            var temp = [];
            commitmentProving[i] = ec.P256.decompress(temp);
        }
        // prepare witness for proving
        var witness = new zkp.PaymentWitness();
        witness.init(hasPrivacy, new common.BigInt(senderSK, 'be', constants.BigIntSize), inputCoins, outputCoins, pkLastByteSender, commitmentProving, commitmentIndexs, myCommitmentIndexs, fee);

        this.Proof =  witness.prove(hasPrivacy);

    }

    sign(hasPrivacy) {
        // Todo:
        this.Sig = [];
    }


}