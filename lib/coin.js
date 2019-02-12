let common = require('./common');
let ec = require('./ec.js');
let P256 = ec.P256;
let constants = require('./constants');
let key = require('./key');
let utils = require('./privacy_utils');
let aes = require('./aes');
let elgamal = require('./elgamal');
let pc = require('./pedersen');
let hybridEnc = require('./hybridEncrypt');

let zeroPoint = ec.P256.curve.point(new common.BigInt(0), new common.BigInt(0));

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

    // hash hashes coin bytes to 32 bytes array
    hash(){
        return common.HashBytesToBytes(this.toBytes())
    }

    // toBytes converts coin to bytes array
    toBytes() {
        let bytes = [];
        // Public key
        if (this.PublicKey != null ) {
            bytes.push(constants.CompressPointSize);
            utils.joinArray(bytes,this.PublicKey.compress());
        } else {
            bytes.push(0x00);
        }

        // Coin commitment
        if (this.CoinCommitment != null) {
            bytes.push(constants.CompressPointSize);
            utils.joinArray(bytes, this.CoinCommitment.compress());
        } else {
            bytes.push(0x00);
        }

        // serial number derivator
        if (this.SNDerivator != null) {
            bytes.push(constants.BigIntSize);
            utils.joinArray(bytes, this.SNDerivator.toArray());
        } else {
            bytes.push(0x00);
        }

        // Serial number
        if (this.SerialNumber != null) {
            bytes.push(constants.CompressPointSize);
            utils.joinArray(bytes, this.SerialNumber.compress());
        } else {
            bytes.push(0x00);
        }

        // randomness
        if (this.Randomness != null) {
            bytes.push(constants.BigIntSize);
            utils.joinArray(bytes, this.Randomness.toArray());
        } else {
            bytes.push(0x00);
        }

        // value
        if (this.Value > 0) {
            let valueBytes = this.Value.toArray()
            bytes.push(valueBytes.length);
            utils.joinArray(bytes, valueBytes);
        } else {
            bytes.push(0x00);
        }

        // info
        if (this.Info != null) {
            bytes.push(this.Info.length);
            utils.joinArray(bytes, this.Info);
        } else {
            bytes.push(0x00);
        }

        return bytes;
    }

    // fromBytes(bytes) {
    //     if (bytes.length === 0) {
    //         return null
    //     }
    //
    //     // Parse Public key
    //     let offset = 0;
    //     let lenField = bytes[offset];
    //     offset += 1;
    //     if (lenField) {
    //         this.PublicKey = P256.decompress(bytes.slice(offset, offset + lenField));
    //         offset += lenField;
    //     }
    //
    //     // Parse Coin commitment
    //     lenField = bytes[offset];
    //     offset += 1;
    //     if (lenField) {
    //         this.CoinCommitment = P256.decompress(bytes.slice(offset, offset + lenField));
    //         offset += lenField;
    //     }
    //
    //     // Parse SNDerivator
    //     lenField = bytes[offset];
    //     offset += 1;
    //     if (lenField) {
    //         this.SNDerivator = new common.BigInt(bytes.slice(offset, offset + lenField));
    //         offset += lenField;
    //     }
    //
    //     // Parse Serial number
    //     lenField = bytes[offset];
    //     offset += 1;
    //     if (lenField) {
    //         this.SerialNumber = P256.decompress(bytes.slice(offset, offset + lenField));
    //         offset += lenField;
    //     }
    //
    //     // Parse Randomness
    //     lenField = bytes[offset];
    //     offset += 1;
    //     if (lenField) {
    //         this.Randomness = new common.BigInt(bytes.slice(offset, offset + lenField));
    //         offset += lenField;
    //     }
    //
    //     // Parse Value
    //     lenField = bytes[offset];
    //     offset += 1;
    //     if (lenField) {
    //         this.Value = new common.BigInt(bytes.slice(offset, offset + lenField));
    //         offset += lenField;
    //     }
    //
    //     // Parse Value
    //     lenField = bytes[offset];
    //     offset += 1;
    //     if (lenField) {
    //         this.Info = bytes.slice(offset, offset + lenField);
    //     }
    //     return this;
    // }

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
        let values = [new common.BigInt(0), this.Value, this.SNDerivator, new common.BigInt(this.getPubKeyLastByte()), this.Randomness];
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
}

class OutputCoin {
    constructor() {
        this.CoinDetails = new Coin();
        this.CoinDetailsEncrypted = new hybridEnc.Ciphertext();
        return this;
    }

    // toBytes converts output coin to bytes array
    toBytes() {
        let bytes = [];
        if (!this.CoinDetailsEncrypted.isNull()){
            let coinDetailsEncryptedBytes = this.CoinDetailsEncrypted.toBytes();
            bytes.push(coinDetailsEncryptedBytes.length);
            utils.joinArray(bytes,coinDetailsEncryptedBytes);
        } else{
            bytes.push(0x00);
        }

        let coinDetailBytes = this.CoinDetails.toBytes();
        bytes.push(coinDetailBytes.length);
        utils.joinArray(bytes, coinDetailBytes);

        return bytes;
    }

    // // fromBytes reverts output coin from bytes array
    // fromBytes(bytes) {
    //     if (bytes.length === 0){
    //         return this;
    //     }
    //
    //     let offset = 0;
    //     let lenCoinDetailEncrypted = bytes[offset];
    //     offset += 1;
    //     if (lenCoinDetailEncrypted) {
    //         this.CoinDetailsEncrypted = new CoinDetailsEncrypted();
    //         this.CoinDetailsEncrypted.fromBytes(bytes.slice(offset, offset + lenCoinDetailEncrypted));
    //         offset += lenCoinDetailEncrypted;
    //     }
    //
    //     let lenCoinDetail = bytes[offset];
    //     offset += 1;
    //     if (lenCoinDetail) {
    //         this.CoinDetails = new Coin();
    //         this.CoinDetails.fromBytes(bytes.slice(offset, offset + lenCoinDetail));
    //     }
    //
    //     return this;
    // }

    // encrypt encrypts output coins using recipient transmission key
    encrypt(recipientTK){
        let valueBytes = this.CoinDetails.Value.toArray();
        let randomnessBytes = utils.AddPaddingBigInt(this.CoinDetails.Randomness, constants.BigIntSize);
        let msg = new Uint8Array(valueBytes.length + constants.BigIntSize);
        msg.set(randomnessBytes, 0);
        msg.set(valueBytes, constants.BigIntSize);

        // let pubKeyPoint = P256.decompress(recipientTK);

        this.CoinDetailsEncrypted = hybridEnc.hybridEncrypt(msg, recipientTK)
    }
}

function TestCoin() {
    let coin = new Coin();
    let keySet = new key.KeySet(key.GenerateSpendingKey([123]));
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
    // let coinBytes = coin.toBytes();
    // console.log('coin bytes :', coinBytes);
    // console.log('coin bytes size :', coinBytes.length);
    //
    // let coin2 = new Coin();
    // coin2.fromBytes(coinBytes);
    // console.log('compare coin: ', coin.eq(coin2));


    /*--------- TEST ENCRYPTION COIN ------------*/
    let outCoin = new OutputCoin();
    outCoin.CoinDetails = coin;
    outCoin.encrypt(keySet.PaymentAddress.TransmisionKey);

    let bytes = outCoin.CoinDetailsEncrypted.toBytes();
    let len = bytes.length;
    console.log('ciphertext: ', bytes.join(', '));
    console.log('len ciphertext: ', outCoin.CoinDetailsEncrypted.toBytes().length);
    // using Golang code to decrypt ciphertext, we receive coin's info exactly
}

// TestCoin();

module.exports = {Coin, InputCoin, OutputCoin};






