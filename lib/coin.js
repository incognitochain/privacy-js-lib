var common = require('./common');
var ec = require('./ec.js');
var constants = require('./constants');

var zeroPoint = ec.Curve.curve.point(new common.BigInt(0), new common.BigInt(0));

class Coin {
    constructor() {
        this.PublicKey = zeroPoint;
        this.CoinCommitment = zeroPoint;
        this.SNDerivator = new common.BigInt(0);
        this.SerialNumber =zeroPoint;
        this.Randomness = new common.BigInt(0);
        this.Value = 0;
        return this;
    }

    // toBytes converts coin to bytes array
    toBytes(){
        var bytes = [];
        // Public key
        if (!this.PublicKey.eq(zeroPoint)){
            bytes.push(ec.Compress(this.PublicKey));
        } else {
            bytes.push(0x00);
        }

        // Coin commitment
        if (!this.CoinCommitment.eq(zeroPoint)){
            bytes.push(ec.Compress(this.CoinCommitment));
        } else {
            bytes.push(0x00);
        }

        // serial number derivator
        if (!this.SNDerivator.eq(new common.BigInt(0))){
            bytes.push(this.SNDerivator.toArray());
        } else {
            bytes.push(0x00);
        }

        // Serial number
        if (!this.SerialNumber.eq(zeroPoint)){
            bytes.push(ec.Compress(this.SerialNumber));
        } else {
            bytes.push(0x00);
        }

        // randomness
        if (!this.Randomness.eq(new common.BigInt(0))){
            bytes.push(this.Randomness.toArray());
        } else {
            bytes.push(0x00);
        }

        // value
        if (this.Value > 0) {
            bytes.push(this.Value.toArray());
        } else{
            bytes.push(0x00);
        }

        return bytes;
    }
}

function TestCoin(){
    var coin = new Coin();
    console.log(coin.toBytes());
}

TestCoin();