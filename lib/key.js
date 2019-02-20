const utils = require('./privacy_utils');
const ec = require('./ec.js');
const constants = require('./constants');
const BigInt = require('bn.js');

// GenerateSpendingKey generates spending key from seed
function GenerateSpendingKey(seed) {
  let spendingKey = utils.hashBytesToBytes(seed);

  // check if spendingKey is less than ec.P256.n
  while (new BigInt(spendingKey).gt(ec.P256.n)) {
    spendingKey = utils.HashBytesToBytes(spendingKey);
  }

  return spendingKey;
}

// GeneratePublicKey generates a public key (address) from spendingKey
function GeneratePublicKey(spendingKey) {
  return (ec.P256.g.mul(new BigInt(spendingKey))).compress();
}

// GenerateReceivingKey generates a receiving key (ElGamal decryption key) from spendingKey
function GenerateReceivingKey(spendingKey) {
  let receivingKey = utils.hashBytesToBytes(spendingKey);

  // check if spendingKey is less than ec.P256.n
  while (new BigInt(receivingKey).gt(ec.P256.n)) {
    receivingKey = utils.HashBytesToBytes(receivingKey);
  }

  return receivingKey;
}

// GenerateTransmissionKey generates a transmission key (ElGamal encryption key) from receivingKey
function GenerateTransmissionKey(receivingKey) {
  return (ec.P256.g.mul(new BigInt(receivingKey))).compress();
}

// ViewingKey consists of publicKey and receivingKey
class ViewingKey {
  constructor() {
    this.PublicKey = [];
    this.ReceivingKey = [];
    return this;
  }

  // fromSpendingKey derives viewingKey from spendingKey
  fromSpendingKey(spendingKey) {
    this.PublicKey = GeneratePublicKey(spendingKey);
    this.ReceivingKey = GenerateReceivingKey(spendingKey);
    return this;
  }

  // toBytes converts viewingKey to a byte array
  toBytes() {
    let viewingKeyBytes = new Uint8Array(constants.VIEWING_KEY_SIZE);
    viewingKeyBytes.set(this.PublicKey, 0);
    viewingKeyBytes.set(this.ReceivingKey, constants.PUBLIC_KEY_SIZE);
    return viewingKeyBytes;
  }
}

// PaymentAddress consists of public key and transmission key
class PaymentAddress {
  // fromSpendingKey derives a payment address corresponding to spendingKey
  fromSpendingKey(spendingKey) {
    this.PublicKey = GeneratePublicKey(spendingKey);
    this.TransmisionKey = GenerateTransmissionKey(GenerateReceivingKey(spendingKey));
    return this;
  }

  // toBytes converts payment address to a byte array
  toBytes() {
    let paymentAddrBytes = new Uint8Array(constants.PAYMENT_ADDR_SIZE);
    paymentAddrBytes.set(this.PublicKey);
    paymentAddrBytes.set(this.TransmisionKey, constants.PUBLIC_KEY_SIZE);
    return paymentAddrBytes;
  }

  // fromBytes converts payment address from bytes array
  // fromBytes(bytes){
  //     this.PublicKey = new Uint8Array(bytes.slice(0, constants.PUBLIC_KEY_SIZE));
  //     console.log(this.PublicKey.length);
  //     this.TransmisionKey = new Uint8Array(bytes.slice(constants.PUBLIC_KEY_SIZE));
  //     return this
  // }
}

class PaymentInfo {
  constructor(paymentAddr, amount) {
    this.PaymentAddress = paymentAddr;
    this.Amount = amount;
    return this;
  }
}

function TestKey() {
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

module.exports = {
  GenerateSpendingKey,
  GeneratePublicKey,
  GenerateTranmissionKey: GenerateTransmissionKey,
  GenerateReceivingKey,
  PaymentAddress,
  ViewingKey,
  PaymentInfo
}