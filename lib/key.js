let utils = require('./privacy_utils');
let ec = require('./ec.js');
let constants = require('./constants');
let BigInt = require('bn.js');

// GenerateSpendingKey generates spending key from seed
function GenerateSpendingKey(seed){
    let spendingKey = utils.HashBytesToBytes(seed);

    // check whether spending key is less than ec.P256.n
    while (new BigInt(spendingKey).gt(ec.P256.n)) {
        spendingKey = utils.HashBytesToBytes(spendingKey);
    }

    return spendingKey;
}

function GeneratePublicKey(spendingKey) {
    return (ec.P256.g.mul(new BigInt(spendingKey))).compress();
}

function GenerateReceivingKey(spendingKey){
    let receivingKey = utils.HashBytesToBytes(spendingKey);

    // check whether spending key is less than ec.P256.n
    while (new BigInt(receivingKey).gt(ec.P256.n)) {
        receivingKey = utils.HashBytesToBytes(receivingKey);
    }

    return receivingKey;
}

function GenerateTransmissionKey(receivingKey) {
    return (ec.P256.g.mul(new BigInt(receivingKey))).compress();
}

// ViewingKey includes Public key and Receiving key
class ViewingKey {
    // computes an viewing key corresponding with spending key
    constructor(){
        this.PublicKey = [];
        this.ReceivingKey = [];
        return this;
    }
    fromSpeningKey(speningKey){
        this.PublicKey = GeneratePublicKey(speningKey);
        this.ReceivingKey = GenerateReceivingKey(speningKey);
        return this;
    }
    toBytes(){
        let viewingKeyBytes = new Uint8Array(constants.ViewingKeySize);
        viewingKeyBytes.set(this.PublicKey, 0);
        viewingKeyBytes.set(this.ReceivingKey, constants.PublicKeySize);
        return viewingKeyBytes;
    }
}

// PaymentAddress includes Public key and Transmission key
class PaymentAddress {
    // constructor(){
    //     return this;
    // }
    // computes an payment address corresponding with spending key
    fromSpendingKey(speningKey){
        this.PublicKey = GeneratePublicKey(speningKey);
        this.TransmisionKey = GenerateTransmissionKey(GenerateReceivingKey(speningKey));
        return this;
    }

    // toBytes converts payment address to bytes array
    toBytes(){
        let paymentAddrBytes = new Uint8Array(constants.PaymentAddrSize);
        paymentAddrBytes.set(this.PublicKey);
        paymentAddrBytes.set(this.TransmisionKey, constants.PublicKeySize);
        return paymentAddrBytes;
    }

    // fromBytes converts payment address from bytes array
    // fromBytes(bytes){
    //     this.PublicKey = new Uint8Array(bytes.slice(0, constants.PublicKeySize));
    //     console.log(this.PublicKey.length);
    //     this.TransmisionKey = new Uint8Array(bytes.slice(constants.PublicKeySize));
    //     return this
    // }
}

class PaymentInfo {
    constructor(paymentAddr, amount){
        this.PaymentAddress = paymentAddr;
        this.Amount = amount;
        return this;
    }
}



function TestKey(){
    let sk = GenerateSpendingKey([123]);
    console.log("Spending key : ", sk);

    let pk = GeneratePublicKey(sk);
    console.log("Public key : ", pk);

    let rk = GenerateReceivingKey(sk);
    console.log('Receiving key: ', rk);

    let tk = GenerateTransmissionKey(rk);
    console.log('Transmission key: ', tk);

    let vk = new ViewingKey(sk);
    console.log('Viewing key: ', vk);

    let paymentAddr = new PaymentAddress().fromSpendingKey(sk);
    console.log('Payment addr: ', paymentAddr);
    // let paymentAddrBytes = paymentAddr.toBytes();

    // let paymentAddr2 = new PaymentAddress().fromBytes(paymentAddrBytes);
    // console.log('Payment addr 2: ', paymentAddr2);
}

// TestKey();

module.exports = {GenerateSpendingKey, GeneratePublicKey, GenerateTranmissionKey: GenerateTransmissionKey, GenerateReceivingKey, PaymentAddress, ViewingKey, PaymentInfo}


