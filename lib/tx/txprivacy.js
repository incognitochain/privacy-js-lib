var common = require('./../common');
var ec = require('./../ec.js');
var P256 = ec.P256;
var constants = require('./../constants');
var key = require('./../key');
var utils = require('./../privacy_utils');
var zkp = require('../zkps/payment');
var coin = require('./../coin');
var schnorr = require('./../schnorr');
var vrf = require('../vrf');
var pc = require('../pedersen');

const TxVersion = 1;
const ConstantID = new Uint8Array(32);
ConstantID[0] = 4;

const TxNormalType = 'n';

function RandomCommitmentsProcess(inputCoins, CMRingSize, db, chainID, tokenID) {
    // just for testing
    var commitmentIndices = [];
    var myCommitmentIndices = [];

    for (let i = 0; i < inputCoins.length*CMRingSize; i++){
        commitmentIndices[i] = 0;
    }

    for (let i = 0; i < inputCoins.length; i++){
        myCommitmentIndices[i]=i*CMRingSize;
    }

    //todo
    return {
        commitmentIndices: commitmentIndices,
        myCommitmentIndices: myCommitmentIndices,
    }
}

class Tx {
    constructor() {
        this.Version = 0;
        this.Type = '';
        this.LockTime = 0;
        this.Fee = 0;

        this.SigPubKey = [];
        this.Sig = [];
        this.Proof = new zkp.PaymentProof();

        this.PubKeyLastByteSender = 0x00;
        this.Metadata = null;

        this.sigPrivKey = [];
    }

    init(senderSK, paymentInfo, inputCoins, fee, hasPrivacy, db, tokenID, metaData) {
        // set version tx
        this.Version = TxVersion;

        // set tokenID for constant
        if (tokenID === null) {
            tokenID = ConstantID;
        }

        // set lock time
        if (this.LockTime === 0) {
            this.LockTime = new Date().getTime();
        }

        // generate sender's key set from senderSK
        var senderKeySet = new key.KeySet(senderSK);

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

        var commitmentIndices = [];   // array index random of commitments in db
        var myCommitmentIndices = [];  // index in array index random of commitment in db

        // get commitment list from db for proving
        // todo:
        // call api to random commitments list
        if (hasPrivacy){
            var randCommitments = RandomCommitmentsProcess(inputCoins, constants.CMRingSize, db, chainID, tokenID);
            commitmentIndices = randCommitments.commitmentIndices;   // array index random of commitments in db
            myCommitmentIndices = randCommitments.myCommitmentIndices;  // index in array index random of commitment in db

            // Check number of list of random commitments, list of random commitment indices
            if (commitmentIndices.length !== inputCoins.length * constants.CMRingSize) {
                return new Error("Invalid random commitments");
            }

            if (myCommitmentIndices.length !== inputCoins.length) {
                return new Error("Number of list my commitment indices must be equal to number of input coins");
            }
        }


        // Calculate sum of all output coins' value
        var sumOutputValue = new common.BigInt(0);
        for (var i = 0; i < paymentInfo.length; i++) {
            sumOutputValue.add(paymentInfo[i].Amount);
        }

        // Calculate sum of all input coins' value
        var sumInputValue = new common.BigInt(0);
        for (var i = 0; i < inputCoins.length; i++) {
            sumInputValue.add(inputCoins[i].CoinDetails.Value);
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
        for (i = 0; i< commitmentIndices.length; i++) {
            //Todo:
            // call api to get commitment by index
            // var temp = db.GetCommitmentByIndex(tokenID, cmIndex, chainID)
            // var temp = [];
            // commitmentProving[i] = ec.P256.curve.decompress(temp);
            commitmentProving[i] =  P256.randomize()
        }

        // for testing

        // prepare witness for proving
        var witness = new zkp.PaymentWitness();
        witness.init(hasPrivacy, new common.BigInt(senderSK, 'be', constants.BigIntSize), inputCoins, outputCoins, pkLastByteSender, commitmentProving, commitmentIndices, myCommitmentIndices, fee);

        this.Proof =  witness.prove(hasPrivacy);

        // set private key for signing tx
        if (hasPrivacy) {
            this.sigPrivKey = [];
            let randSK = witness.RandSK;
            this.sigPrivKey = utils.joinArray(senderSK, randSK.toArray());

            // encrypt coin details (Randomness)
            // hide information of output coins except coin commitments, public key, snDerivators
            for (i = 0; i < this.Proof.OutputCoins.length; i++) {
                this.Proof.OutputCoins[i].Encrypt(paymentInfo[i].PaymentAddress.PublicKey);
                this.Proof.OutputCoins[i].CoinDetails.SerialNumber = null;
                this.Proof.OutputCoins[i].CoinDetails.Value = 0;
                this.Proof.OutputCoins[i].CoinDetails.Randomness = null;
            }

            // hide information of input coins except serial number of input coins
            for (i = 0; i < this.Proof.InputCoins.length; i++) {
                this.Proof.InputCoins[i].CoinDetails.CoinCommitment = null;
                this.Proof.InputCoins[i].CoinDetails.Value = 0;
                this.Proof.InputCoins[i].CoinDetails.SNDerivator = null;
                this.Proof.InputCoins[i].CoinDetails.PublicKey = null;
                this.Proof.InputCoins[i].CoinDetails.Randomness = null;
            }

        } else {
            this.sigPrivKey = [];
            let randSK = new common.BigInt(0);
            this.sigPrivKey = utils.joinArray(senderSK, randSK.toArray())
        }

        // sign tx
        this.PubKeyLastByteSender = pkLastByteSender;
        this.sign(hasPrivacy);

        return null;
    }

    sign(hasPrivacy) {
        //Check input transaction
        if (this.Sig.length !== 0) {
            return new Error("input transaction must be an unsigned one")
        }

        /****** using Schnorr signature *******/
        // sign with sigPrivKey
        // prepare private key for Schnorr
        var sk = new common.BigInt(this.sigPrivKey.slice(0, constants.BigIntSize));
        var r = new common.BigInt(this.sigPrivKey.slice(constants.BigIntSize));


        var sigKey = new schnorr.SchnPrivKey(sk, r);

        // save public key for verification signature tx
        this.SigPubKey = sigKey.PK.PK.compress();
        console.log('Sig PubKey: ', this.SigPubKey);

        // signing
        this.Sig = sigKey.Sign(this.hash());
        return null
    }

    hash(){
        //Todo
        var record = this.Version.toString();
        record += this.LockTime.toString();
        record += this.Fee.toString();
        if (this.Proof != null) {
            record += this.Proof.toBytes().toString();
        }
        if (this.Metadata != null) {
            record += this.Metadata;
        }
        return common.DoubleHashBytesToBytes(record);
    }
}


function TestTx(){
    let tx = new Tx();

    let skSender = key.GenerateSpendingKey([123]);

    let skReceiver = [];
    skReceiver[0] = key.GenerateSpendingKey([1]);
    skReceiver[1] = key.GenerateSpendingKey([1]);

    let paymentInfo = [];
    paymentInfo[0] = new key.PaymentInfo(new key.PaymentAddress().fromSpendingKey(skReceiver[0]), new common.BigInt(5));
    paymentInfo[1] = new key.PaymentInfo(new key.PaymentAddress().fromSpendingKey(skReceiver[1]), new common.BigInt(4));

    let inputCoins = [];
    let snderivators = [];
    snderivators[0] = utils.RandInt();
    snderivators[1] = utils.RandInt();

    inputCoins[0] = new coin.InputCoin();
    inputCoins[0].CoinDetails.set(P256.decompress(key.GeneratePublicKey(skReceiver[0])),
        snderivators[0], vrf.Eval(new common.BigInt(skReceiver[0]), snderivators[0], pc.PedCom.G[constants.SK]),
        utils.RandInt(), new common.BigInt(10), null);

    inputCoins[1] = new coin.InputCoin();
    inputCoins[1].CoinDetails.set(P256.decompress(key.GeneratePublicKey(skReceiver[1])),
        snderivators[1], vrf.Eval(new common.BigInt(skReceiver[1]), snderivators[1], pc.PedCom.G[constants.SK]),
        utils.RandInt(), new common.BigInt(10), null);


    tx.init(skSender, paymentInfo, inputCoins, new common.BigInt(0), true, null, null, null);
    console.log('tx : ', tx);
}

TestTx();