var common = require('./common');
var hash = require('hash.js');
var ec = require('./ec.js');

class SpendingKey {
    // generates a random SpendingKey correspond with seed
    constructor(seed){
        var spendingKey = hash.sha256().update(seed).digest('Uint32Array');

        // check whether spending key is less than curve.Params.N
        do {
            var spendingKeyInt = new common.BigInt(spendingKey, 10);
        }
        while (spendingKeyInt.gt(ec.Curve.n)) {
            spendingKey = hash.sha256().update(spendingKeyInt).digest('Uint32Array');
        }

        this.SpendingKey = spendingKey;
        return this;
    }
}

class PublicKey {
    // computes an public key corresponding with spendingKey
    constructor(spendingKey){
        var pk = ec.Curve.g.mul(spendingKey);
        this.PublicKey = ec.Compress(pk);
        return this;
    }

    GetSize(){
        return this.PublicKey.length;
    }
}

var seed = new Uint8Array(1)
seed[0] = 123
var sk = new SpendingKey(seed);
console.log(sk.SpendingKey);
var skInt = new common.BigInt(sk.SpendingKey, 10);
var pk = new PublicKey(skInt);
console.log(pk.PublicKey);
// console.log(pk.GetSize())



// var hashData = hash.sha256().update('abc').digest('sha256')
// var hashData = hash.sha256().update('abc').digest('Uint32Array')
// console.log(hashData)
// console.log(typeof (hashData))
// console.log(hashData.length)
//

// var mybigInt = new common.BigInt(10)

// var a = new common.BigInt('900000000000000000000000000000000000', 10)
// var b = new common.BigInt('200000000000000000000000000000000000', 10)
//
// var CurveN = new common.BigInt('50001000000000000000000', 10)
// var N = new common.BigInt.mont(CurveN)
//
// var redA = a.toRed(N)
// var redB = b.toRed(N)
//
// // console.log(redA.toString(10))
// // console.log(redB.toString(10))
//
// var redC = redA.redSub(redB)
//
// var a2 = redC.fromRed()
//
// console.log(a2.toString())
//
//
//
// var c = a.sub(b)
// c = c.mod(CurveN)
// console.log(c.toString())
//
//
// var red = common.BigInt.mont(new common.BigInt(13));
// var a = new common.BigInt(20).toRed(red);
// var b = new common.BigInt(7).toRed(red);
// var c = a.redAdd(b);
//
// console.log(c.toNumber())


