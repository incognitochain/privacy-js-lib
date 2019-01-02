var common = require('./common');
var ec = require('./ec.js');
var constants = require('./constants');
// var uint64be = require('int64-buffer').Uint64BE;
var key = require('./key');
var utils = require('./privacy_utils');

var zeroPoint = ec.P256.curve.point(new common.BigInt(0), new common.BigInt(0));

class Coin {
    constructor() {
        this.PublicKey = zeroPoint;
        this.CoinCommitment = zeroPoint;
        this.SNDerivator = new common.BigInt(0);
        this.SerialNumber =zeroPoint;
        this.Randomness = new common.BigInt(0);
        this.Value = new common.BigInt(0);
        return this;
    }

    // toBytes converts coin to bytes array
    toBytes(){
        var bytes = [];
        // Public key
        if (!this.PublicKey.eq(zeroPoint)){
            bytes.push(ec.CompressPointSize);
            bytes.push(this.PublicKey.compress());
        } else {
            bytes.push(0x00);
        }

        // Coin commitment
        if (!this.CoinCommitment.eq(zeroPoint)){
            bytes.push(ec.CompressPointSize);
            bytes.push(this.CoinCommitment.compress());
        } else {
            bytes.push(0x00);
        }

        // serial number derivator
        if (!this.SNDerivator.eq(new common.BigInt(0))){
            bytes.push(ec.BigIntSize);
            bytes.push(this.SNDerivator.toArray());
        } else {
            bytes.push(0x00);
        }

        // Serial number
        if (!this.SerialNumber.eq(zeroPoint)){
            bytes.push(ec.CompressPointSize);
            bytes.push(this.SerialNumber.compress());
        } else {
            bytes.push(0x00);
        }

        // randomness
        if (!this.Randomness.eq(new common.BigInt(0))){
            bytes.push(ec.BigIntSize);
            bytes.push(this.Randomness.toArray());
        } else {
            bytes.push(0x00);
        }

        // value
        if (this.Value > 0) {
            bytes.push(ec.BigIntSize);
            bytes.push(this.Value.toArray());
        } else{
            bytes.push(0x00);
        }

        return bytes;
    }

    fromBytes(bytes){
        if (bytes.length === 0){
            return null
        }

        // Parse Public key
        var offset = 0;
        var lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            // console.log ('TESTTTTTTTTTT: ', bytes.slice(offset, offset + lenField));
            this.PublicKey = ec.P256.decompress(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Coin commitment
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.CoinCommitment = ec.P256.decompress(bytes.slice(offset, offset + lenField));
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
            this.SerialNumber = ec.P256.decompress(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Randomness
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.SNDerivator = new common.BigInt(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Value
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.Value = uint64be(bytes.slice(offset, offset + lenField));
        }
        return this;
    }

    // eq return true if this = targetCoin
    eq(targetCoin){
        if (!this.PublicKey.eq(targetCoin.PublicKey)){
            return false;
        }
        if (!this.CoinCommitment.eq(targetCoin.CoinCommitment)){
            return false;
        }
        if (!this.SNDerivator.eq(targetCoin.SNDerivator)){
            return false;
        }
        if (!this.SerialNumber.eq(targetCoin.SerialNumber)){
            return false;
        }
        if (!this.Randomness.eq(targetCoin.Randomness)){
            return false;
        }
        if (!this.Value.eq(targetCoin.Value)){
            return false;
        }
        return true;
    }

    //
}

function TestCoin(){
    var coin = new Coin();
    var spendingKey = key.GenerateSpendingKey([123]);
    var publicKey = key.GeneratePublicKey(spendingKey);

    coin.PublicKey = ec.Decompress(publicKey);
    coin.Value = new common.BigInt(10);
    coin.Randomness = utils.RandInt(ec.BigIntSize);
    coin.SNDerivator = utils.RandInt(ec.BigIntSize);

    var coinBytes = coin.toBytes();
    console.log('coin bytes :', coinBytes);

    var coin2 = new Coin().fromBytes(coinBytes);
    console.log('compare coin: ', coin.eq(coin2));
}

TestCoin();


// var a = uint64be(10);
// console.log(a);
// var aBytes = a.toArray();
// console.log(aBytes);
//
// var b = uint64be(aBytes);
// console.log(b);


/*-------------------------- TEST COMPRESS/DECOMPRESS POINT --------------------------*/
// var point = ec.P256.g;
// console.log('point1: ', point);
//
// var pointBytes = ec.Compress(point);
//
// var point2 = ec.Decompress(pointBytes);
// console.log('point2: ', point2);

// var point = ec.Decompress([
//     3, 71, 166, 83, 226, 71, 95, 14, 188, 57, 177, 14, 85, 249, 136, 146, 169, 160, 86, 50, 207, 24, 120, 71, 251, 247, 227, 93, 147, 22, 190, 2, 80]);



class InputCoin {
    constructor() {
        this.CoinDetails = new Coin();
        return this;
    }

    // toBytes converts input coin to bytes array
    toBytes(){
        return this.CoinDetails.toBytes();
    }

    // fromBytes co
    fromBytes(bytes){
        this.CoinDetails.fromBytes(bytes);
        return this;
    }
}

class OutputCoin {
    constructor() {
        this.CoinDetails = new Coin();
        this.CoinDetailsEncrypted = [];
        return this;
    }

    // toBytes converts input coin to bytes array
    toBytes(){
        return this.CoinDetails.toBytes();
    }

    // fromBytes co
    fromBytes(bytes){
        this.CoinDetails.fromBytes(bytes);
        return this;
    }
}