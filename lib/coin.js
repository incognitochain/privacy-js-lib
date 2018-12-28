var common = require('./common');
var ec = require('./ec.js');
var constants = require('./constants');
var uint64be = require('int64-buffer').Uint64BE;
var key = require('./key');
var utils = require('./privacy_utils');

var zeroPoint = ec.Curve.curve.point(new common.BigInt(0), new common.BigInt(0));

class Coin {
    constructor() {
        this.PublicKey = zeroPoint;
        this.CoinCommitment = zeroPoint;
        this.SNDerivator = new common.BigInt(0);
        this.SerialNumber =zeroPoint;
        this.Randomness = new common.BigInt(0);
        this.Value = new uint64be(0);
        return this;
    }

    // toBytes converts coin to bytes array
    toBytes(){
        var bytes = [];
        // Public key
        if (!this.PublicKey.eq(zeroPoint)){
            bytes.push(ec.Compress(PointSize));
            bytes.push(ec.Compress(this.PublicKey));
        } else {
            bytes.push(0x00);
        }

        // Coin commitment
        if (!this.CoinCommitment.eq(zeroPoint)){
            bytes.push(ec.CompressPointSize);
            bytes.push(ec.Compress(this.CoinCommitment));
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
            bytes.push(ec.Compress(this.SerialNumber));
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
            var valueBytes = this.Value.toArray();
            bytes.push(valueBytes.length);
            bytes.push(valueBytes);
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
            this.PublicKey = ec.Decompress(bytes.slice(offset, offset + lenField));
            offset += lenField;
        }

        // Parse Coin commitment
        lenField = bytes[offset];
        offset += 1;
        if (lenField) {
            this.CoinCommitment = ec.Decompress(bytes.slice(offset, offset + lenField));
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
            this.SerialNumber = ec.Decompress(bytes.slice(offset, offset + lenField));
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
}

function TestCoin(){
    var coin = new Coin();
    var spendingKey = key.GenerateSpendingKey([123]);
    var publicKey = key.GeneratePublicKey(spendingKey);

    coin.PublicKey = ec.Decompress(publicKey);
    coin.Value = uint64be(10);
    coin.Randomness = new utils.PrivacyUtils().RandInt(ec.BigIntSize);
    console.log(coin.toBytes());
}

// TestCoin();


var a = uint64be(10);
console.log(a);
var aBytes = a.toArray();
console.log(aBytes);

var b = uint64be(aBytes);
console.log(b);