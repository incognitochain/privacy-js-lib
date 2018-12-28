var common = require('./common');
var ec = require('./ec.js');
var constants = require('./constants');

class Coin {
    constructor() {
        this.PublicKey = ec.Curve.curve.point(new common.BigInt(0), new common.BigInt(0));
        this.CoinCommitment = ec.Curve.curve.point(new common.BigInt(0), new common.BigInt(0));
        this.SNDerivator = new common.BigInt(0);
        this.SerialNumber = ec.Curve.curve.point(new common.BigInt(0), new common.BigInt(0));
        this.Randomness = new common.BigInt(0);
        this.Value = 0;
        return this;
    }

    // toBytes converts coin to bytes array
    // toBytes(){
    //    if this.PublicKey.
    // }
}

function TestCoin(){
    var coin = new Coin()
    console.log(coin)
}

TestCoin()