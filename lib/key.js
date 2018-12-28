var common = require('./common');
var hash = require('hash.js');
var ec = require('./ec.js');
var constants = require('./constants');

// SpendingKey 32 bytes
// class SpendingKey {
//     // generates a random SpendingKey correspond with seed
//     constructor(seed){
//         var spendingKey = common.HashBytesToBytes(seed);
//
//         // check whether spending key is less than curve.Params.N
//         while (new common.BigInt(spendingKey, 10, 'be').gt(ec.Curve.n)) {
//             spendingKey = common.HashBytesToBytes(spendingKey);
//         }
//
//         this.SpendingKey = spendingKey;
//         return this;
//     }
// }

// GenerateSpendingKey generates spending key from seed
function GenerateSpendingKey(seed){
    var spendingKey = common.HashBytesToBytes(seed);

    // check whether spending key is less than curve.Params.N
    while (new common.BigInt(spendingKey, 10, 'be').gt(ec.Curve.n)) {
        spendingKey = common.HashBytesToBytes(spendingKey);
    }

    return spendingKey;
}


// PublicKey 33 bytes
// class PublicKey {
//     // computes an public key corresponding with spendingKey
//     constructor(spendingKey){
//         var pk = ec.Curve.g.mul(new common.BigInt(spendingKey, 10, 'be'));
//
//         this.PublicKey = ec.Compress(pk);
//         return this;
//     }
// }

function GeneratePublicKey(spendingKey) {
    return ec.Compress(ec.Curve.g.mul(new common.BigInt(spendingKey, 10, 'be')));
}

// ReceivingKey 32 bytes
// class ReceivingKey {
//     // computes an receiving key corresponding with spendingKey
//     constructor(spendingKey){
//         var rk = common.HashBytesToBytes(spendingKey);
//
//         this.ReceivingKey = rk;
//         return this;
//     }
// }

function GenerateReceivingKey(spendingKey){
    return common.HashBytesToBytes(spendingKey);
}


// TransmissionKey 33 bytes
// class TransmissionKey {
//     // computes an transmission key corresponding with receiving key
//     constructor(receivingKey){
//         var tk = ec.Curve.g.mul(new common.BigInt(receivingKey, 10, 'be'));
//
//         this.TransmissionKey = ec.Compress(tk);
//         return this;
//     }
// }

function GenerateTranmissionKey(receivingKey) {
    return ec.Compress(ec.Curve.g.mul(new common.BigInt(receivingKey, 10, 'be')));
}

// ViewingKey includes Public key and Receiving key
class ViewingKey {
    // computes an viewing key corresponding with spending key
    constructor(speningKey){
        this.PublicKey = GeneratePublicKey(speningKey);
        this.ReceivingKey = GenerateReceivingKey(speningKey);
        return this;
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
        this.TransmisionKey = GenerateTranmissionKey(GenerateReceivingKey(speningKey));
        return this;
    }

    // toBytes converts payment address to bytes array
    toBytes(){
        var paymentAddrBytes = new Uint8Array(constants.PaymentAddrSize);
        paymentAddrBytes.set(this.PublicKey);
        paymentAddrBytes.set(this.TransmisionKey, constants.TransmissionKeySize);
        return paymentAddrBytes;
    }

    // fromBytes converts payment address from bytes array
    fromBytes(bytes){
        this.PublicKey = new Uint8Array(bytes.slice(0, constants.PublicKeySize));
        console.log(this.PublicKey.length)
        this.TransmisionKey = new Uint8Array(bytes.slice(constants.PublicKeySize));
        return this
    }
}


function TestKey(){
    var sk = GenerateSpendingKey([123]);
    console.log("Spending key : ", sk);

    var pk = GeneratePublicKey(sk);
    console.log("Public key : ", pk);

    var rk = GenerateReceivingKey(sk);
    console.log('Receiving key: ', rk);

    var tk = GenerateTranmissionKey(rk);
    console.log('Transmission key: ', tk);

    var vk = new ViewingKey(sk);
    console.log('Viewing key: ', vk);

    var paymentAddr = new PaymentAddress().fromSpendingKey(sk);
    console.log('Payment addr: ', paymentAddr);
    var paymentAddrBytes = paymentAddr.toBytes();

    var paymentAddr2 = new PaymentAddress().fromBytes(paymentAddrBytes);
    console.log('Payment addr 2: ', paymentAddr2);

}

TestKey();


