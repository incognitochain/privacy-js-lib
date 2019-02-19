const ec = require('../../ec.js');
const P256 = ec.P256;
const constants = require('../../constants');
const key = require('../../key');
const utils = require('../../privacy_utils');
const zkp = require('../../zkps/payment');
const coin = require('../../coin');
const schnorr = require('../../schnorr');
const elGamal = require('../../elgamal');
const axios = require('axios');
const base58 = require('../../base58');
const keyWallet = require('../wallet/hdwallet');
const constantsWallet = require('../wallet/constants');
const bn = require('../../../node_modules/bn.js/lib/bn');
const httpRequest = require('../../httprequest/request');

const TxVersion = 1;
const ConstantID = new Uint8Array(32);
ConstantID[0] = 4;

const TxNormalType = 'n';

// GetOutputCoin returns list of all output coins of user that has viewingKey.PublicKey,
async function GetOutputCoin(paymentAdrr, viewingKey) {
    const data = {
        "jsonrpc": "1.0",
        "method": "listoutputcoins",
        "params": [
            0,
            999999,
            [{
                // "PaymentAddress":"1Uv3VB24eUszt5xqVfB87ninDu7H43gGxdjAUxs9j9JzisBJcJr7bAJpAhxBNvqe8KNjM5G9ieS1iC944YhPWKs3H2US2qSqTyyDNS4Ba",
                // "ReadonlyKey":"1CvjKR6j8VfrNdr55RicSN9CK6kyhRHGzDhfq9Lwru6inWS5QBNJE2qvSfDUz7ZpVwBjMUoSQp6FDdaa9WjjQymN8BRpVczD5dmiEzw2"
                "PaymentAddress": paymentAdrr,
                "ReadonlyKey": viewingKey,
            }]
        ],
        "id": 1
    };

    const response = await httpRequest.requestAPI(data);

    if (response.status !== 200) {
        return {
            outCoins: [],
            err: new Error("Can't request API")
        }
    } else{
        return {
            outCoins: response.data.Result.Outputs[viewingKey],
            err: null
        }
    }
}



// ChooseBestCoinToSpent return list of coin to spent using Knapsack and Greedy algorithm
//todo: 0xakk0r0kamui
function ChooseBestCoinToSpent(inputCoins, amount) {

}

// CheckExistSerialNumber return true if snd existed in database
async function HasSerialNumber(paymentAddr, serialNumberStrs) {
    const data = {
        "jsonrpc": "1.0",
        "method": "hasserialnumbers",
        "params": [
            // ["1Uv3VB24eUszt5xqVfB87ninDu7H43gGxdjAUxs9j9JzisBJcJr7bAJpAhxBNvqe8KNjM5G9ieS1iC944YhPWKs3H2US2qSqTyyDNS4Ba",        // paynment address
            // ["15mm7h9mRRyWH7S2jU4p9brQ8zeomooAHhQpRsruoWgA6hKHCuV", "15mm7h9mRRyWH7S2jU4p9brQ8zeomooAHhQpRsruoWgA6hKHCuV"]],     // array of serial number strings

            paymentAddr,
            serialNumberStrs,
        ],
        "id": 1
    };

    const response = await httpRequest.requestAPI(data);

    console.log("Response: ", response);
    if (response.status !== 200) {
        return {
            existed: [],
            err: new Error("Can't request API")
        }
    } else{
        return {
            existed : response.data.Result,
            err: null
        }
    }
}


// CheckExistSND return true if snd existed in database
function CheckExistSND(snd) {
    return false
}


// RandomCommitmentsProcess randoms list commitment for proving
function RandomCommitmentsProcess(inputCoins, CMRingSize, db, chainID, tokenID) {
    // just for testing
    let commitmentIndices = new Array(inputCoins.length * CMRingSize);
    let myCommitmentIndices = new Array(inputCoins.length);

    for (let i = 0; i < inputCoins.length * CMRingSize; i++) {
        commitmentIndices[i] = 0;
    }

    for (let i = 0; i < inputCoins.length; i++) {
        myCommitmentIndices[i] = i * CMRingSize;
    }

    //todo
    return {
        commitmentIndices: commitmentIndices,
        myCommitmentIndices: myCommitmentIndices,
    }
}


async function prepareInputForTx(spendingKeyStr) {

    // deserialize spending key string to key wallet
    spendingKeyStr = "112t8rqGc71CqjrDCuReGkphJ4uWHJmiaV7rVczqNhc33pzChmJRvikZNc3Dt5V7quhdzjWW9Z4BrB2BxdK5VtHzsG9JZdZ5M7yYYGidKKZV";
    let myKeyWallet = keyWallet.KeyWallet.base58CheckDeserialize(spendingKeyStr);

    // import key set
    myKeyWallet.KeySet.importFromPrivateKey(myKeyWallet.KeySet.PrivateKey);

    // serialize payment address, readonlyKey
    let paymentAddrSerialize = myKeyWallet.base58CheckSerialize(constantsWallet.PaymentAddressType);
    let readOnlyKeySerialize = myKeyWallet.base58CheckSerialize(constantsWallet.ReadonlyKeyType);
    console.log("paymentAddrSerialize: ", paymentAddrSerialize);
    console.log("readOnlyKeySerialize: ", readOnlyKeySerialize);

    // get all output coins of spendingKey
    let res = await GetOutputCoin(paymentAddrSerialize, readOnlyKeySerialize);
    let allOutputCoinStrs;
    if (res.err === null){
        allOutputCoinStrs = res.outCoins
    } else{
        console.log('ERR when call API get output: ', res.err);
    }

    let inputCoins = new Array(allOutputCoinStrs.length);
    let serialNuberStrs = new Array(allOutputCoinStrs.length);

    console.log("output coin string 0: ", allOutputCoinStrs[0]);

    // console.log("input: ", inputCoins);
    // parse all output coin strings to input coin struct which is input for init tx function
    for (let i = 0; i < allOutputCoinStrs.length; i++) {

        let publicKeyDecode = base58.checkDecode(allOutputCoinStrs[i].PublicKey).bytesDecoded;
        let commitmentDecode = base58.checkDecode(allOutputCoinStrs[i].CoinCommitment).bytesDecoded;
        let sndDecode = base58.checkDecode(allOutputCoinStrs[i].SNDerivator).bytesDecoded;
        let randDecode = base58.checkDecode(allOutputCoinStrs[i].Randomness).bytesDecoded;

        console.log("publicKeyDecode", publicKeyDecode.join(", "));
        console.log("commitmentDecode", commitmentDecode.join(", "));
        console.log("sndDecode", sndDecode.join(", "));
        console.log("randDecode", randDecode.join(", "));


        inputCoins[i] = new coin.InputCoin();
        inputCoins[i].CoinDetails.set(P256.decompress(publicKeyDecode),
            P256.decompress(commitmentDecode),
            new bn.BN(sndDecode),
            null,
            new bn.BN(randDecode),
            allOutputCoinStrs[i].Value,
            base58.checkDecode(allOutputCoinStrs[i].Info).bytesDecoded);

        // calculate serial number for all of output coins
        inputCoins[i].CoinDetails.SerialNumber = P256.g.derive(new bn.BN(myKeyWallet.KeySet.PrivateKey), new bn.BN(allOutputCoinStrs[i].SNDerivator));
        console.log("serial number: ",inputCoins[i].CoinDetails.SerialNumber.compress() );

        serialNuberStrs[i] = base58.checkEncode(inputCoins[i].CoinDetails.SerialNumber.compress(), 0x00);


    }

    console.log();
    console.log();
    console.log("all output coin after calculating serial number: ", inputCoins);
    console.log("all output coin after calculating serial number: ", inputCoins.length);

    // check whether each input coin is spent or not
    let resSN = await HasSerialNumber(paymentAddrSerialize, serialNuberStrs);
    let existed = [];
    if (resSN.err !== null){
        console.log('ERR when call API has serial number: ', res.err);
    }else{
        existed = resSN.existed;
    }
    console.log("sn not existed: ", existed);
    console.log("sn not existed len : ", existed.length);


    // let response2
}

// prepareInputForTx("");

class Tx {
    constructor() {
        // Basic data
        this.Version = 0;
        this.Type = '';
        this.LockTime = 0;
        this.Fee = 0;
        this.Info = [];

        // Sign and Privacy proof
        this.SigPubKey = [];
        this.Sig = [];
        this.Proof = new zkp.PaymentProof();

        this.PubKeyLastByteSender = 0x00;

        // Metadata
        this.Metadata = null;

        this.sigPrivKey = []; // is ALWAYS private property of struct, if privacy: 64 bytes, and otherwise, 32 bytes
    }

    init(senderSK, paymentInfo, inputCoins, fee, hasPrivacy, db, tokenID, metaData) {
        let start = new Date().getTime();
        let i;
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
        let senderKeySet = new key.KeySet(senderSK);

        // get public key's last byte of sender
        let senderPK = senderKeySet.PaymentAddress.PublicKey;
        let pkLastByteSender = senderPK[senderPK.length - 1];

        // init info of tx
        let pubKeyData = P256.decompress(senderKeySet.PaymentAddress.PublicKey);
        this.Info = elGamal.Encrypt(senderKeySet.PaymentAddress.TransmisionKey, pubKeyData);

        //set meta data
        this.Metadata = metaData;

        // check whether tx is custom token tx or not
        if (inputCoins.length === 0 && fee === 0 && !hasPrivacy) {
            console.log("CREATE TX CUSTOM TOKEN");
            this.Fee = fee;
            this.sigPrivKey = senderSK;
            this.PubKeyLastByteSender = pkLastByteSender;

            this.sign(hasPrivacy);
            return;
        }

        // set type tx
        this.Type = TxNormalType;

        // set shard id
        //todo:
        let shardID = pkLastByteSender % constants.SHARD_NUMBER;

        // Calculate sum of all output coins' value
        let sumOutputValue = new bn(0);
        for (i = 0; i < paymentInfo.length; i++) {
            if (paymentInfo[i].Amount.cmp(0) === -1) {
                return new Error("output coin's value is less than 0");
            }
            sumOutputValue = sumOutputValue.add(paymentInfo[i].Amount);
        }

        // Calculate sum of all input coins' value
        let sumInputValue = new bn(0);
        for (i = 0; i < inputCoins.length; i++) {
            sumInputValue.add(inputCoins[i].CoinDetails.Value);
        }

        // Calculate over balance, it will be returned to sender
        let overBalance = sumInputValue.sub(sumOutputValue);
        overBalance = overBalance.sub(fee);

        if (overBalance.lt(0)) {
            return new Error("Input value less than output value");
        }

        let commitmentIndices = []; // array index random of commitments in db
        let myCommitmentIndices = []; // index in array index random of commitment in db
        let commitmentProving = [];

        // get commitment list from db for proving
        // todo:
        // call api to random commitments list
        if (hasPrivacy) {
            let randCommitments = RandomCommitmentsProcess(inputCoins, constants.CMRingSize, db, chainID, tokenID);
            commitmentIndices = randCommitments.commitmentIndices; // array index random of commitments in db
            myCommitmentIndices = randCommitments.myCommitmentIndices; // index in array index random of commitment in db

            // Check number of list of random commitments, list of random commitment indices
            if (commitmentIndices.length !== inputCoins.length * constants.CMRingSize) {
                return new Error("Invalid random commitments");
            }

            if (myCommitmentIndices.length !== inputCoins.length) {
                return new Error("Number of list my commitment indices must be equal to number of input coins");
            }
            // get list of commitments for proving one-out-of-many from commitmentIndexs
            commitmentProving = new Array(inputCoins.length * constants.CMRingSize);
            for (i = 0; i < commitmentIndices.length; i++) {
                //Todo:
                // call api to get commitment by index
                // let temp = db.GetCommitmentByIndex(tokenID, cmIndex, chainID)
                // let temp = [];
                // commitmentProving[i] = ec.P256.curve.decompress(temp);
                commitmentProving[i] = P256.randomize()
            }
        }

        // if overBalance > 0, create a new payment info with pk is sender's pk and amount is overBalance
        if (overBalance.gt(0)) {
            let changePaymentInfo = new key.PaymentInfo();
            changePaymentInfo.Amount = overBalance;
            changePaymentInfo.PaymentAddress = senderKeySet.PaymentAddress;
            paymentInfo.push(changePaymentInfo);
        }

        // create new output coins
        let outputCoins = new Array(paymentInfo.length);

        // generates SNDs for output coins
        let ok = true;
        let sndOuts = new Array(paymentInfo.length);
        while (ok) {
            let sndOut = new bn(0);
            for (i = 0; i < paymentInfo.length; i++) {
                sndOut = utils.RandInt(constants.BigIntSize);
                while (true) {
                    //todo:
                    // call api to check SND existence
                    // let ok1 = CheckSNDerivatorExistence(tokenID, sndOut, chainID, db)
                    let ok1 = false;

                    // if sndOut existed, then re-random it
                    if (ok1) {
                        sndOut = utils.RandInt(constants.BigIntSize);
                    } else {
                        break
                    }
                }
                sndOuts[i] = sndOut;
            }
            // if sndOuts has two elements that have same value, then re-generates it
            ok = utils.checkDuplicateBigIntArray(sndOuts);
            if (ok) {
                sndOuts = new Array(paymentInfo.length);
            }
        }

        // create new output coins with info: Pk, value, last byte of pk, snd
        for (i = 0; i < paymentInfo.length; i++) {
            outputCoins[i] = new coin.OutputCoin();
            outputCoins[i].CoinDetails.Value = paymentInfo[i].Amount;
            outputCoins[i].CoinDetails.PublicKey = P256.decompress(paymentInfo[i].PaymentAddress.PublicKey);
            outputCoins[i].CoinDetails.SNDerivator = sndOuts[i];
        }

        // assign fee tx
        this.Fee = fee;

        // create zero knowledge proof of payment
        this.Proof = new zkp.PaymentProof();

        // prepare witness for proving
        let witness = new zkp.PaymentWitness();
        witness.init(hasPrivacy, new bn(senderSK, 'be', constants.BigIntSize), inputCoins, outputCoins, pkLastByteSender, commitmentProving, commitmentIndices, myCommitmentIndices, fee);

        this.Proof = witness.prove(hasPrivacy);

        // set private key for signing tx
        if (hasPrivacy) {
            this.sigPrivKey = new Uint8Array(2 * constants.BigIntSize);
            this.sigPrivKey.set(senderSK, 0);
            this.sigPrivKey.set(witness.randSK.toArray('be', constants.BigIntSize), senderSK.length);

            // encrypt coin details (Randomness)
            // hide information of output coins except coin commitments, public key, snDerivators
            for (i = 0; i < this.Proof.outputCoins.length; i++) {
                this.Proof.outputCoins[i].encrypt(paymentInfo[i].PaymentAddress.PublicKey);
                this.Proof.outputCoins[i].CoinDetails.SerialNumber = null;
                this.Proof.outputCoins[i].CoinDetails.Value = 0;
                this.Proof.outputCoins[i].CoinDetails.Randomness = null;
            }

            // hide information of input coins except serial number of input coins
            for (i = 0; i < this.Proof.inputCoins.length; i++) {
                this.Proof.inputCoins[i].CoinDetails.CoinCommitment = null;
                this.Proof.inputCoins[i].CoinDetails.Value = 0;
                this.Proof.inputCoins[i].CoinDetails.SNDerivator = null;
                this.Proof.inputCoins[i].CoinDetails.PublicKey = null;
                this.Proof.inputCoins[i].CoinDetails.Randomness = null;
            }

        } else {
            this.sigPrivKey = new Uint8Array(constants.BigIntSize + 1);
            this.sigPrivKey.set(senderSK, 0);
            this.sigPrivKey.set(new bn(0).toArray(), senderSK.length);
        }

        // sign tx
        this.PubKeyLastByteSender = pkLastByteSender;
        this.sign();

        let end = new Date().getTime();
        console.log("Creating tx time: ", end - start);

        return null;
    }

    sign() {
        //Check input transaction
        if (this.Sig.length !== 0) {
            return new Error("input transaction must be an unsigned one")
        }

        /****** using Schnorr signature *******/
            // sign with sigPrivKey
            // prepare private key for Schnorr
        let sk = new bn(this.sigPrivKey.slice(0, constants.BigIntSize));
        let r = new bn(this.sigPrivKey.slice(constants.BigIntSize));

        let sigKey = new schnorr.SchnPrivKey(sk, r);

        // save public key for verification signature tx
        this.SigPubKey = sigKey.PK.PK.compress();
        console.log('Sig PubKey: ', this.SigPubKey);

        // signing
        this.Sig = sigKey.sign(this.hash());
        return null
    }

    // toString converts tx to string
    toString() {
        let record = this.Version.toString();
        record += this.LockTime.toString();
        record += this.Fee.toString();
        if (this.Proof != null) {
            record += this.Proof.toBytes().toString();
        }
        if (this.Metadata != null) {
            record += this.Metadata;
        }
        return record;
    }

    // hash hashes tx string to 32-byte hashing value
    hash() {
        return utils.DoubleHashBytesToBytes(this.toString());
    }

    // getTxActualSize computes the actual size of a given transaction in kilobyte
    getTxActualSize() {
        let sizeTx = 1 + this.Type.length + this.LockTime.toString().length + this.Fee.toString().length + this.Info.length;
        sizeTx += this.SigPubKey.length + this.Sig.length;

        if (this.Proof !== null) {
            sizeTx += this.Proof.toBytes();
        }

        sizeTx += 1;

        if (this.Metadata !== null) {
            // TODO 0xjackpolope
        }

        return Math.ceil(sizeTx / 1024);
    }
}


async function TestTx() {
    // let tx = new Tx();
    //
    // let skSender = key.GenerateSpendingKey([123]);
    //
    // let skReceiver = [];
    // skReceiver[0] = key.GenerateSpendingKey([1]);
    // skReceiver[1] = key.GenerateSpendingKey([1]);
    //
    // let paymentInfo = [];
    // paymentInfo[0] = new key.PaymentInfo(new key.PaymentAddress().fromSpendingKey(skReceiver[0]), new BigInt(5));
    // paymentInfo[1] = new key.PaymentInfo(new key.PaymentAddress().fromSpendingKey(skReceiver[1]), new BigInt(4));
    //
    // let inputCoins = [];
    // let snderivators = [];
    // snderivators[0] = utils.RandScalar();
    // snderivators[1] = utils.RandScalar();
    //
    // inputCoins[0] = new coin.InputCoin();
    // inputCoins[0].CoinDetails.set(P256.decompress(key.GeneratePublicKey(skReceiver[0])),
    //     snderivators[0], pc.PedCom.G[constants.SK].derive(new BigInt(skReceiver[0]), snderivators[0]),
    //     utils.RandScalar(), new BigInt(10), null);
    //
    // inputCoins[1] = new coin.InputCoin();
    // inputCoins[1].CoinDetails.set(P256.decompress(key.GeneratePublicKey(skReceiver[1])),
    //     snderivators[1], pc.PedCom.G[constants.SK].derive(new BigInt(skReceiver[1]), snderivators[1]),
    //     utils.RandScalar(), new BigInt(10), null);
    //
    //
    // let err  = tx.init(skSender, paymentInfo, inputCoins, new BigInt(0), true, null, null, null);
    // if (err != null){
    //     console.log("Error when creating tx: ", err)
    // }
    // console.log('tx : ', tx);


    let spendingKeyStr = "112t8rqGc71CqjrDCuReGkphJ4uWHJmiaV7rVczqNhc33pzChmJRvikZNc3Dt5V7quhdzjWW9Z4BrB2BxdK5VtHzsG9JZdZ5M7yYYGidKKZV";
    let keyWallet1 = keyWallet.KeyWallet.base58CheckDeserialize(spendingKeyStr);
    let keySet = keyWallet.KeyWallet.getKeySet(spendingKeyStr);
    keyWallet1.KeySet = keySet;

    // let spendingKeyBytes = base58.CheckDecode(spendingKeyStr).bytesDecoded;
    //
    // console.log('spendingKeyBytes: ', spendingKeyBytes.join(', '));
    // console.log('spendingKeyBytes len : ', spendingKeyBytes.length);
    // let keySet = new key.KeySet(spendingKeyBytes);
    //
    // console.log('Key set: ', keySet);

    let paymentAddrSerialize = keyWallet1.base58CheckSerialize(constantsWallet.PaymentAddressType);
    let readOnlyKeySerialize = keyWallet1.base58CheckSerialize(constantsWallet.ReadonlyKeyType);
    console.log("paymentAddrSerialize: ", paymentAddrSerialize);
    console.log("readOnlyKeySerialize: ", readOnlyKeySerialize);

    let res = await GetOutputCoin(paymentAddrSerialize, readOnlyKeySerialize);
    if (res.status === 200) {
        console.log('res: ', res.Result.Outputs);
    }

    // let sk = key.GenerateSpendingKey([123]);
    // console.log("sk bytes : ", sk);
    // console.log("sk bytes to string : ", sk.toString());
    // let skStr = base58.CheckEncode(sk, 1);
    // console.log("sk string : ", skStr);

}

// TestTx();