const ec = require('../../ec.js');
const P256 = ec.P256;
const constants = require('../../constants');
const key = require('../../key');
const keySet = require('../../keyset');
const utils = require('../../privacy_utils');
const zkp = require('../../zkps/payment');
const coin = require('../../coin');
const schnorr = require('../../schnorr');
const elGamal = require('../../elgamal');
const axios = require('axios');
const base58 = require('../../base58');
const keyWallet = require('../wallet/hdwallet');
const constantsWallet = require('../wallet/constants');
const bn = require('bn.js');
const httpRequest = require('../../httprequest/request');
let knapsack = require('../../knapsack').knapsack;
let greedy = require('../../knapsack').greedy;
const json = require('circular-json');

const common = require('../common');

const TxVersion = 1;
const ConstantID = new Uint8Array(32);
ConstantID[0] = 4;

const TxNormalType = 'n';

// GetOutputCoin returns list of all output coins of user that has viewingKey.PublicKey,
async function getOutputCoin(paymentAdrr, viewingKey) {
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
    } else {
        return {
            outCoins: response.data.Result.Outputs[viewingKey],
            err: null
        }
    }
}

// ParseCoinFromStr convert input coin string to struct
function parseInputCoinFromStr(coinStrs, keyWallet) {
    let inputCoins = new Array(coinStrs.length);

    let spendingKeyBN = new bn.BN(keyWallet.KeySet.PrivateKey);

    for (let i = 0; i < coinStrs.length; i++) {

        let publicKeyDecode = base58.checkDecode(coinStrs[i].PublicKey).bytesDecoded;
        let commitmentDecode = base58.checkDecode(coinStrs[i].CoinCommitment).bytesDecoded;
        let sndDecode = base58.checkDecode(coinStrs[i].SNDerivator).bytesDecoded;
        let randDecode = base58.checkDecode(coinStrs[i].Randomness).bytesDecoded;

        // console.log("publicKeyDecode", publicKeyDecode.join(", "));
        // console.log("commitmentDecode", commitmentDecode.join(", "));
        // console.log("sndDecode", sndDecode.join(", "));
        // console.log("randDecode", randDecode.join(", "));

        inputCoins[i] = new coin.InputCoin();

        inputCoins[i].CoinDetails.set(P256.decompress(publicKeyDecode),
            P256.decompress(commitmentDecode),
            new bn.BN(sndDecode),
            null,
            new bn.BN(randDecode),
            new bn.BN(coinStrs[i].Value),
            base58.checkDecode(coinStrs[i].Info).bytesDecoded);

        // calculate serial number for all of output coins

        inputCoins[i].CoinDetails.SerialNumber = P256.g.derive(spendingKeyBN, new bn.BN(inputCoins[i].CoinDetails.SNDerivator));
    }

    return inputCoins;
}

async function getUnspentCoin(inputCoins, paymentAddrSerialize, inCoinStrs) {
    let unspentCoin = new Array();
    let unspentCoinStrs = new Array();

    let serialNumberStrs = new Array(inputCoins.length);

    for (let i = 0; i < inputCoins.length; i++) {
        serialNumberStrs[i] = base58.checkEncode(inputCoins[i].CoinDetails.SerialNumber.compress(), 0x00);
    }

    // check whether each input coin is spent or not
    let res = await hasSerialNumber(paymentAddrSerialize, serialNumberStrs);
    let existed = [];
    if (res.err !== null) {
        console.log('ERR when call API has serial number: ', res.err);
    } else {
        existed = res.existed;
    }

    for (let i = 0; i < existed.length; i++) {
        if (!existed[i]) {
            unspentCoin.push(inputCoins[i]);
            unspentCoinStrs.push(inCoinStrs[i]);
        }
    }
    // console.log("unspent input coin: ", unspentCoin);
    // console.log("unspent input coin len : ", unspentCoin.length);
    return {
        unspentCoin: unspentCoin,
        unspentCoinStrs: unspentCoinStrs
    };
}


// chooseBestCoinToSpent return list of coin to spent using Knapsack and Greedy algorithm
//todo: 0xakk0r0kamui
function chooseBestCoinToSpent(inputCoins, amount) {
    let incoinUnknapsack = [];
    let incoinKnapsack = [];
    let valueKnapsack = [];
    let resultOutputCoins = [];
    let remainOutputCoins = [];
    let sumvalueKnapsack = new bn(0);
    for (let i = 0; i < inputCoins.length; i++) {
        if (inputCoins[i].CoinDetails.Value.cmp(amount) > 0) {
            incoinUnknapsack.push(inputCoins[i]);
        } else {
            sumvalueKnapsack = sumvalueKnapsack.add(inputCoins[i].CoinDetails.Value);
            valueKnapsack.push(inputCoins[i].CoinDetails.Value.toNumber());
            incoinKnapsack.push(inputCoins[i]);
        }
    }
    let target = sumvalueKnapsack.clone().sub(amount);
    let totalResultOutputCoinAmount = new bn(0);
    if (target.cmpn(1000) > 0) {
        inputCoins.sort(function(a,b){return a.CoinDetails.Value.cmp(b.CoinDetails.Value)});
        let choices = greedy(inputCoins, amount);
        for (let i = 0; i < inputCoins.length; i++) {
            if (choices[i]) {
                totalResultOutputCoinAmount = totalResultOutputCoinAmount.add(inputCoins[i].CoinDetails.Value);
                resultOutputCoins.push(inputCoins[i]);
            } else {
                remainOutputCoins.push(inputCoins[i]);
            }
        }
    } else if (target.cmpn(0) > 0) {
        let choices = knapsack(valueKnapsack, target.toNumber());
        for (let i = 0; i < valueKnapsack.length; i++) {
            if (choices[i]) {
                totalResultOutputCoinAmount = totalResultOutputCoinAmount.addn(valueKnapsack[i]);
                resultOutputCoins.push(inputCoins[i]);
            } else {
                remainOutputCoins.push(inputCoins[i]);
            }
        }
    } else if (target == 0) {
        totalResultOutputCoinAmount = sumvalueKnapsack;
        resultOutputCoins = incoinKnapsack;
        remainOutputCoins = incoinUnknapsack;
    } else {
        if (incoinUnknapsack.length == 0) {
            throw new Error("Not enough coin");
        } else {
            let iMin = 0;
            for (let i = 1; i < incoinUnknapsack.length; i++) {
                iMin = (incoinUnknapsack[i].CoinDetails.Value.cmp(incoinUnknapsack[iMin].CoinDetails.Value) < 0) ? (i) : (iMin);
            }
            resultOutputCoins.push(incoinUnknapsack[iMin]);
            totalResultOutputCoinAmount = incoinUnknapsack[iMin].CoinDetails.Value.clone();
            for (let i = 0; i < incoinUnknapsack.length; i++) {
                if (i != iMin) {
                    remainOutputCoins.push(incoinUnknapsack[i]);
                }
            }
        }
    }
    return {
        resultOutputCoins: resultOutputCoins,
        remainOutputCoins: remainOutputCoins,
        totalResultOutputCoinAmount: totalResultOutputCoinAmount
    };
}

// hasSerialNumber return true if snd existed in database
async function hasSerialNumber(paymentAddr, serialNumberStrs) {
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

    // console.log("Response: ", response);
    if (response.status !== 200) {
        return {
            existed: [],
            err: new Error("Can't request API")
        }
    } else {
        return {
            existed: response.data.Result,
            err: null
        }
    }
}


// hasSNDerivator return true if snd existed in database
async function hasSNDerivator(paymentAddr, snds) {
    //todo:

    const data = {
        "jsonrpc": "1.0",
        "method": "hassnderivators",
        "params": [
            // ["1Uv3VB24eUszt5xqVfB87ninDu7H43gGxdjAUxs9j9JzisBJcJr7bAJpAhxBNvqe8KNjM5G9ieS1iC944YhPWKs3H2US2qSqTyyDNS4Ba",        // paynment address
            // ["15mm7h9mRRyWH7S2jU4p9brQ8zeomooAHhQpRsruoWgA6hKHCuV", "15mm7h9mRRyWH7S2jU4p9brQ8zeomooAHhQpRsruoWgA6hKHCuV"]],     // array of serial number strings

            paymentAddr,
            snds,
        ],
        "id": 1
    };

    const response = await httpRequest.requestAPI(data);

    // console.log("Response: ", response);
    if (response.status !== 200) {
        return {
            existed: [],
            err: new Error("Can't request API")
        }
    } else {
        return {
            existed: response.data.Result,
            err: null
        }
    }
    // return false
}


// randomCommitmentsProcess randoms list commitment for proving
async function randomCommitmentsProcess(paymentAddr, inputCoinStrs) {
    const data = {
        "jsonrpc": "1.0",
        "method": "randomcommitments",
        "params": [
            paymentAddr,
            inputCoinStrs,
            // [
            //     {
            //         "PublicKey": "177KNe6pRhi97hD9LqjUvGxLoNeKh9F5oSeh99V6Td2sQcm7qEu",
            //         "CoinCommitment": "15iYzoFTsoE2xkRe8cb2HbWeEBUoejZCBedV8e14xXiJjBPCHtX",
            //         "SNDerivator": "1gkrfYsYoria5TQMqYTzqnXutgdgqPvXwhMHk7q2UaZmjvkDnA",
            //         "SerialNumber": "",
            //         "Randomness": "1M59rHeaXwDNfWoDTRh6QNPPUSLizfcrK14ic9cJTo2pjzxtLR",
            //         "Value": 1000000,
            //         "Info": "1Wh4bh"
            //     }
            // ]
        ],
        "id": 1
    };

    const response = await httpRequest.requestAPI(data);

    // console.log("Response: ", response);
    if (response.status !== 200) {
        return {
            commitmentIndices: [],
            commitments: [],
            myCommitmentIndices: [],
            err: new Error("Can't request API")
        }
    } else {

        let commitmentStrs = response.data.Result.Commitments;

        console.log("Len commitment: ", commitmentStrs.length);

        // deserialize commitments
        let commitments = new Array(commitmentStrs.length);
        for (let i=0; i<commitments.length; i++){
            let res = base58.checkDecode(commitmentStrs[i]);

            if (res.version !== constants.PRIVACY_VERSION){
                return {
                    commitmentIndices: [],
                    commitments: [],
                    myCommitmentIndices: [],
                    err: new Error("Base58 check decode wrong version")
                }
            }

            commitments[i]= P256.decompress(res.bytesDecoded);
        }

        return {
            commitmentIndices: response.data.Result.CommitmentIndices,
            commitments: commitments,
            myCommitmentIndices: response.data.Result.MyCommitmentIndexs,
            err: null
        }
    }
}


async function prepareInputForTx(spendingKeyStr, paymentInfos) {
    // deserialize spending key string to key wallet
    // spendingKeyStr = "112t8rqGc71CqjrDCuReGkphJ4uWHJmiaV7rVczqNhc33pzChmJRvikZNc3Dt5V7quhdzjWW9Z4BrB2BxdK5VtHzsG9JZdZ5M7yYYGidKKZV";
    spendingKeyStr = "112t8rqnMrtPkJ4YWzXfG82pd9vCe2jvWGxqwniPM5y4hnimki6LcVNfXxN911ViJS8arTozjH4rTpfaGo5i1KKcG1ayjiMsa4E3nABGAqQh";
    let myKeyWallet = keyWallet.KeyWallet.base58CheckDeserialize(spendingKeyStr);

    // import key set
    myKeyWallet.KeySet.importFromPrivateKey(myKeyWallet.KeySet.PrivateKey);

    // console.log("Private key: ", myKeyWallet.KeySet.PrivateKey.join(', '));

    // serialize payment address, readonlyKey
    let paymentAddrSerialize = myKeyWallet.base58CheckSerialize(constantsWallet.PaymentAddressType);
    let readOnlyKeySerialize = myKeyWallet.base58CheckSerialize(constantsWallet.ReadonlyKeyType);
    // console.log("paymentAddrSerialize: ", paymentAddrSerialize);
    // console.log("readOnlyKeySerialize: ", readOnlyKeySerialize);

    // get all output coins of spendingKey
    let res = await getOutputCoin(paymentAddrSerialize, readOnlyKeySerialize);
    let allOutputCoinStrs;
    // console.log("res :",res);
    if (res.err === null) {
        allOutputCoinStrs = res.outCoins
    } else {
        console.log('ERR when call API get output: ', res.err);
    }

    // parse input coin from string
    let inputCoins = parseInputCoinFromStr(allOutputCoinStrs, myKeyWallet);

    // get unspent coin
    let resGetUnspentCoin = await getUnspentCoin(inputCoins, paymentAddrSerialize, allOutputCoinStrs);
    let unspentCoins = resGetUnspentCoin.unspentCoin;
    let unspentCoinStrs = resGetUnspentCoin.unspentCoinStrs;


    // console.log("Unspent coin: ", unspentCoins);

    // calculate amount which need to be spent
    let amount = new bn.BN(0);
    for (let i = 0; i < paymentInfos.length; i++) {
        amount = amount.add(paymentInfos[i].Amount);
    }

    //for test random commitment
    // let response = await randomCommitmentsProcess(paymentAddrSerialize, [allOutputCoinStrs[0]]);
    // console.log();
    // console.log();
    // console.log("response random commitment: ", response);

    // for test hassnd
    // let response = await hasSNDerivator(paymentAddrSerialize, [allOutputCoinStrs[0].SNDerivator]);
    // console.log("response random commitment: ", response);

    // get coin to spent using Knapsack
    return {
        senderKeySet: myKeyWallet.KeySet,
        paymentAddrSerialize: paymentAddrSerialize,
        inputCoins: chooseBestCoinToSpent(unspentCoins, amount).resultOutputCoins,
        inputCoinStrs: unspentCoinStrs,
    };
}

// prepareInputForTx("", paymentInfos);

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

    async init(senderSK, paymentAddrSerialize,  paymentInfo, inputCoins, inputCoinStrs, fee, hasPrivacy, db, tokenID, metaData) {
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
        let senderKeySet = new keySet.KeySet().importFromPrivateKey(senderSK);

        // get public key's last byte of sender
        let senderPK = senderKeySet.PaymentAddress.PublicKey;
        let pkLastByteSender = senderPK[senderPK.length - 1];

        // init info of tx
        let pubKeyData = P256.decompress(senderKeySet.PaymentAddress.PublicKey);
        let transmissionKeyPoint = P256.decompress(senderKeySet.PaymentAddress.TransmissionKey);
        this.Info = elGamal.encrypt(transmissionKeyPoint, pubKeyData);

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
        let shardID = common.getShardIDFromLastByte(pkLastByteSender);

        // Calculate sum of all output coins' value
        let sumOutputValue = new bn(0);
        for (i = 0; i < paymentInfo.length; i++) {
            if (paymentInfo[i].Amount.cmp(new bn.BN(0)) === -1) {
                return new Error("output coin's value is less than 0");
            }
            sumOutputValue = sumOutputValue.add(paymentInfo[i].Amount);
        }

        // Calculate sum of all input coins' value
        let sumInputValue = new bn(0);
        console.log("CREATING TX: ------ INPUT COIN LEN",   inputCoins.length);
        for (i = 0; i < inputCoins.length; i++) {
            sumInputValue = sumInputValue.add(inputCoins[i].CoinDetails.Value);
        }

        // Calculate over balance, it will be returned to sender
        let overBalance = sumInputValue.sub(sumOutputValue);
        overBalance = overBalance.sub(fee);

        if (overBalance.lt(new bn.BN(0))) {
            return new Error("Input value less than output value");
        }

        let commitmentIndices = []; // array index random of commitments in db
        let myCommitmentIndices = []; // index in array index random of commitment in db
        let commitmentProving = [];

        // get commitment list from db for proving
        // call api to random commitments list

        // console.log("my Commitment: ", inputCoins[0].CoinDetails.CoinCommitment);
        if (hasPrivacy) {
            let randCommitments = await randomCommitmentsProcess(paymentAddrSerialize, inputCoinStrs);
            // console.log("randCommitments: ", randCommitments);
            // console.log();
            // console.log();
            commitmentIndices = randCommitments.commitmentIndices; // array index random of commitments in db
            myCommitmentIndices = randCommitments.myCommitmentIndices; // index in array index random of commitment in db
            commitmentProving = randCommitments.commitments;

            // Check number of list of random commitments, list of random commitment indices
            if (commitmentIndices.length !== inputCoins.length * constants.CM_RING_SIZE) {
                return new Error("Invalid random commitments");
            }

            if (myCommitmentIndices.length !== inputCoins.length) {
                return new Error("Number of list my commitment indices must be equal to number of input coins");
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
        // let sndOutStrs = new Array(paymentInfo.length);

        while (ok) {
            let sndOut = new bn(0);
            for (i = 0; i < paymentInfo.length; i++) {
                sndOut = utils.randScalar();
                let sndOutStrs = base58.checkEncode(sndOut.toArray(), constants.PRIVACY_VERSION);

                while (true) {
                    // call api to check SND existence
                    let res = await hasSNDerivator(paymentAddrSerialize, [sndOutStrs]);

                    // if sndOut existed, then re-random it
                    if (res.existed[0]) {
                        sndOut = utils.randScalar();
                        sndOutStrs = base58.checkEncode(sndOut.toArray(), constants.PRIVACY_VERSION);
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
        witness.init(hasPrivacy, new bn(senderSK, 'be', constants.BIG_INT_SIZE), inputCoins, outputCoins, pkLastByteSender, commitmentProving, commitmentIndices, myCommitmentIndices, fee);

        this.Proof = witness.prove(hasPrivacy);

        // set private key for signing tx
        if (hasPrivacy) {
            this.sigPrivKey = new Uint8Array(2 * constants.BIG_INT_SIZE);
            this.sigPrivKey.set(senderSK, 0);
            this.sigPrivKey.set(witness.randSK.toArray('be', constants.BIG_INT_SIZE), senderSK.length);

            // encrypt coin details (Randomness)
            // hide information of output coins except coin commitments, public key, snDerivators
            for (i = 0; i < this.Proof.outputCoins.length; i++) {
                this.Proof.outputCoins[i].encrypt(paymentInfo[i].PaymentAddress.TransmissionKey);
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
            this.sigPrivKey = new Uint8Array(constants.BIG_INT_SIZE + 1);
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
        let sk = new bn(this.sigPrivKey.slice(0, constants.BIG_INT_SIZE));
        let r = new bn(this.sigPrivKey.slice(constants.BIG_INT_SIZE));

        let sigKey = new schnorr.SchnPrivKey(sk, r);

        // save public key for verification signature tx
        this.SigPubKey = sigKey.PK.PK.compress();
        // console.log('Sig PubKey: ', this.SigPubKey);

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
        return utils.doubleHashBytesToBytes(this.toString());
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
    let n = 1;
    let paymentInfos = new Array(n);

    let receiverSpendingKeyStr1 = "112t8rqGc71CqjrDCuReGkphJ4uWHJmiaV7rVczqNhc33pzChmJRvikZNc3Dt5V7quhdzjWW9Z4BrB2BxdK5VtHzsG9JZdZ5M7yYYGidKKZV";
    let receiverKeyWallet1 = keyWallet.KeyWallet.base58CheckDeserialize(receiverSpendingKeyStr1);

    // import key set
    receiverKeyWallet1.KeySet.importFromPrivateKey(receiverKeyWallet1.KeySet.PrivateKey);

    paymentInfos[0] = new key.PaymentInfo(receiverKeyWallet1.KeySet.PaymentAddress, new bn.BN(23));

    let res = await prepareInputForTx("", paymentInfos);
    let tx = new Tx();
    // console.log();
    // console.log();
    // console.log("---------- BEFORE CREATE TX res input coin strs : ", res.inputCoinStrs);


    await tx.init(res.senderKeySet.PrivateKey, res.paymentAddrSerialize,  paymentInfos, res.inputCoins, res.inputCoinStrs, new bn.BN(0), true, null, null, null);
    console.log("***************Tx: ", tx);

    await sendTx(tx);
    // console.log("res: ", res);

}

// TestTx();


async function sendTx(tx){
    let txJson = json.parse(tx);
    console.log(txJson);

    let txSerialize = base58.checkEncode(txJson, constants.PRIVACY_VERSION);


    // const data = {
    //     "jsonrpc": "1.0",
    //     "method": "sendtransaction",
    //     "params": [
    //         0,
    //         999999,
    //         [{
    //             // "PaymentAddress":"1Uv3VB24eUszt5xqVfB87ninDu7H43gGxdjAUxs9j9JzisBJcJr7bAJpAhxBNvqe8KNjM5G9ieS1iC944YhPWKs3H2US2qSqTyyDNS4Ba",
    //             // "ReadonlyKey":"1CvjKR6j8VfrNdr55RicSN9CK6kyhRHGzDhfq9Lwru6inWS5QBNJE2qvSfDUz7ZpVwBjMUoSQp6FDdaa9WjjQymN8BRpVczD5dmiEzw2"
    //             "PaymentAddress": paymentAdrr,
    //             "ReadonlyKey": viewingKey,
    //         }]
    //     ],
    //     "id": 1
    // };
    //
    // const response = await httpRequest.requestAPI(data);
    //
    // if (response.status !== 200) {
    //     return {
    //         outCoins: [],
    //         err: new Error("Can't request API")
    //     }
    // } else {
    //     return {
    //         outCoins: response.data.Result.Outputs[viewingKey],
    //         err: null
    //     }
    // }


}