var common = require('./common');
var ec = require('./ec.js');
var P256 = ec.P256;
var constants = require('./constants');
var key = require('./key');
var utils = require('./privacy_utils');
var aes = require('./aes');
var elgamal = require('./elgamal');
var pc = require('./pedersen');

var zeroPoint = ec.P256.curve.point(new common.BigInt(0), new common.BigInt(0));

class Coin {
    constructor() {
        this.PublicKey = zeroPoint;
        this.CoinCommitment = zeroPoint;
        this.SNDerivator = new common.BigInt(0);
        this.SerialNumber = zeroPoint;
        this.Randomness = new common.BigInt(0);
        this.Value = new common.BigInt(0);
        this.Info = new Uint8Array(0);
        return this;
    }

    set(publicKey, snd, serialNumber, randomness, value, info){
        this.PublicKey = publicKey;
        this.SNDerivator = snd;
        this.SerialNumber = serialNumber;
        this.Randomness = randomness;
        this.Value = value;
        this.Info = info;
        this.commitAll();
        return this;
    }

    // toBytes converts coin to bytes array
    toBytes() {
        var bytes = [];
        // Public key
        if (!this.PublicKey.eq(zeroPoint)) {
            bytes.push(constants.CompressPointSize);
            utils.joinArray(bytes,this.PublicKey.compress());
        } else {
            bytes.push(0x00);
        }

        // Coin commitment
        if (!this.CoinCommitment.eq(zeroPoint)) {
            bytes.push(constants.CompressPointSize);
            utils.joinArray(bytes, this.CoinCommitment.compress());
        } else {
            bytes.push(0x00);
        }

        // serial number derivator
        if (!this.SNDerivator.eq(new common.BigInt(0))) {
            bytes.push(constants.BigIntSize);
            utils.joinArray(bytes, this.SNDerivator.toArray());
        } else {
            bytes.push(0x00);
        }

        // Serial number
        if (!this.SerialNumber.eq(zeroPoint)) {
            bytes.push(constants.CompressPointSize);
            utils.joinArray(bytes, this.SerialNumber.compress());
        } else {
            bytes.push(0x00);
        }

        // randomness
        if (!this.Randomness.eq(new common.BigInt(0))) {
            bytes.push(constants.BigIntSize);
            utils.joinArray(bytes, this.Randomness.toArray());
        } else {
            bytes.push(0x00);
        }

        // value
        if (this.Value > 0) {
            var valueBytes = this.Value.toArray()
            bytes.push(valueBytes.length);
            utils.joinArray(bytes, valueBytes);
        } else {
            bytes.push(0x00);
        }

        // info
        if (this.Info.length > 0) {
            bytes.push(this.Info.length);
            utils.joinArray(bytes, this.Info);
        } else {
            bytes.push(0x00);
        }

        return bytes;
    }

    fromBytes(bytes) {
        if (bytes.length === 0) {
            return null
        }

        // Parse Public key
        var offset = 0;
        var lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.PublicKey = P256.decompress(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Coin commitment
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.CoinCommitment = P256.decompress(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse SNDerivator
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.SNDerivator = new common.BigInt(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Serial number
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.SerialNumber = P256.decompress(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Randomness
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.Randomness = new common.BigInt(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Value
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.Value = new common.BigInt(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Value
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.Info = bytes.slice(offset, offset + lenField);
        }
        return this;
    }

    // eq return true if this = targetCoin
    eq(targetCoin) {
        if (!this.PublicKey.eq(targetCoin.PublicKey)) {
            return false;
        }
        if (!this.CoinCommitment.eq(targetCoin.CoinCommitment)) {
            return false;
        }
        if (!this.SNDerivator.eq(targetCoin.SNDerivator)) {
            return false;
        }
        if (!this.SerialNumber.eq(targetCoin.SerialNumber)) {
            return false;
        }
        if (!this.Randomness.eq(targetCoin.Randomness)) {
            return false;
        }
        if (!this.Value.eq(targetCoin.Value)) {
            return false;
        }
        return true;
    }

    commitAll(){
        var values = [new common.BigInt(0), this.Value, this.SNDerivator, new common.BigInt(this.getPubKeyLastByte()), this.Randomness];
        this.CoinCommitment = pc.PedCom.CommitAll(values);
        this.CoinCommitment = this.CoinCommitment.add(this.PublicKey)

    }
    getPubKeyLastByte(){
        let pubKeyBytes = this.PublicKey.compress();
        return pubKeyBytes[pubKeyBytes.length-1];
    }
}

class InputCoin {
    constructor() {
        this.CoinDetails = new Coin();
        return this;
    }

    // toBytes converts input coin to bytes array
    toBytes() {
        return this.CoinDetails.toBytes();
    }

    // fromBytes co
    fromBytes(bytes) {
        if (bytes.length == 0){
            return this
        }
        this.CoinDetails.fromBytes(bytes);
        return this;
    }
}

class CoinDetailsEncrypted {
    constructor(){
        this.EncryptedRandomness = new Uint8Array(0);
        this.EncryptedValue = new Uint8Array(0);
        this.EncryptedSymKey = new Uint8Array(0);
        return this;
    }
    isNull(){
        if (this.EncryptedRandomness.length === 0){
            return true;
        }
        if (this.EncryptedValue.length === 0){
            return true;
        }
        if (this.EncryptedSymKey.length === 0){
            return true;
        }
        return false;
    }

    toBytes(){
        var bytes = [];
        if (this.isNull()){
            return bytes;
        }
        utils.joinArray(bytes, this.EncryptedRandomness);
        utils.joinArray(bytes, this.EncryptedSymKey);
        utils.joinArray(bytes, this.EncryptedValue);
        return bytes;
    }

    fromBytes(bytes){
        if (bytes.length === 0){
            return this;
        }

        this.EncryptedRandomness = bytes.slice(0, constants.EncryptedRandomnessSize);
        this.EncryptedSymKey = bytes.slice(constants.EncryptedRandomnessSize, constants.EncryptedRandomnessSize + constants.EncryptedSymKeySize);
        this.EncryptedValue = bytes.slice(constants.EncryptedRandomnessSize + constants.EncryptedSymKeySize);

        return this;
    }
}

class OutputCoin {
    constructor() {
        this.CoinDetails = new Coin();
        this.CoinDetailsEncrypted = new CoinDetailsEncrypted();
        return this;
    }

    // toBytes converts output coin to bytes array
    toBytes() {
        var bytes = [];
        if (!this.CoinDetailsEncrypted.isNull()){
            var coinDetailsEncryptedBytes = this.CoinDetailsEncrypted.toBytes();
            bytes.push(coinDetailsEncryptedBytes.length);
            utils(bytes,coinDetailsEncryptedBytes);
        } else{
            bytes.push(0x00);
        }

        var coinDetailBytes = this.CoinDetails.toBytes();
        bytes.push(coinDetailBytes.length);
        utils(bytes, coinDetailBytes);

        return bytes;
    }

    // fromBytes reverts output coin from bytes array
    fromBytes(bytes) {
        if (bytes.length === 0){
            return this;
        }

        var offset = 0;
        var lenCoinDetailEncrypted = bytes[offset];
        offset += 1;
        if (lenCoinDetailEncrypted) {
            this.CoinDetailsEncrypted = new CoinDetailsEncrypted();
            this.CoinDetailsEncrypted.fromBytes(bytes.slice(offset, offset + lenCoinDetailEncrypted));
            offset += lenCoinDetailEncrypted;
        }

        var lenCoinDetail = bytes[offset];
        offset += 1;
        if (lenCoinDetail) {
            this.CoinDetails = new Coin();
            this.CoinDetails.fromBytes(bytes.slice(offset, offset + lenCoinDetail));
        }

        return this;
    }

    // encrypt encrypts output coins using recipient transmission key
    encrypt(recipientTK){
        // Generate a AES key as the abscissa of a random elliptic point
        var aesKeyPoint = P256.randomize();
        var aesKeyByte = aesKeyPoint.getX().toArray('be',32);

        // Encrypt coin details using aesKeyByte
        var aesScheme = new aes.AES(aesKeyByte);

        // Encrypt coin randomness
        this.CoinDetailsEncrypted = new CoinDetailsEncrypted();

        var randomnessBytes = this.CoinDetails.Randomness.toArray();
        this.CoinDetailsEncrypted.EncryptedRandomness = aesScheme.Encrypt(randomnessBytes);

        // Encrypt coin value
        var valueBytes = this.CoinDetails.Value.toArray();
        this.CoinDetailsEncrypted.EncryptedValue = aesScheme.Encrypt(valueBytes);

        // Encrypt aesKeyPoint under recipient's transmission key using ElGamal cryptosystem
        this.CoinDetailsEncrypted.EncryptedSymKey = elgamal.Encrypt(recipientTK, aesKeyPoint);
        return this;
    }
}

function TestCoin() {
    var coin = new Coin();
    var keySet = new key.KeySet(key.GenerateSpendingKey([123]));
    // console.log(keySet.PaymentAddress.PublicKey);
    // console.log('viewingKey : ', keySet.ReadonlyKey);

    coin.PublicKey = P256.decompress(keySet.PaymentAddress.PublicKey);
    coin.Value = new common.BigInt(10);
    coin.Randomness = utils.RandInt(constants.BigIntSize);
    coin.SNDerivator = utils.RandInt(constants.BigIntSize);

    console.log('coin.Randomness: ', coin.Randomness.toArray());
    console.log('coin.SNDerivator: ', coin.SNDerivator.toArray());

    // console.log('coin info plaintext', coin.Randomness.toArray());

    /*--------- TEST COIN BYTES ------------*/
    // var coinBytes = coin.toBytes();
    // console.log('coin bytes :', coinBytes);
    // console.log('coin bytes size :', coinBytes.length);
    //
    // var coin2 = new Coin();
    // coin2.fromBytes(coinBytes);
    // console.log('compare coin: ', coin.eq(coin2));


    /*--------- TEST ENCRYPTION COIN ------------*/
    // var outCoin = new OutputCoin();
    // outCoin.CoinDetails = coin;
    // outCoin.encrypt(keySet.PaymentAddress.TransmisionKey);
    //
    // var bytes = outCoin.CoinDetailsEncrypted.toBytes();
    // var len = bytes.length;
    // console.log('ciphertext: ', bytes.join(', '));
    // console.log('len ciphertext: ', outCoin.CoinDetailsEncrypted.toBytes().length);

    var ciphertext = elgamal.Encrypt(keySet.PaymentAddress.TransmisionKey, P256.randomize());
    console.log(ciphertext.length);
    console.log('ciphertext: ', ciphertext.join(', '));

    var plaintext = elgamal.Decrypt(keySet.ReadonlyKey.ReceivingKey, ciphertext);
    console.log('Plain text decrypt: ', plaintext);
}

// TestCoin();


module.exports = {Coin, InputCoin, OutputCoin};






