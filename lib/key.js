var common = require('./common');
var hash = require('hash.js');
var ec = require('./ec.js');

class SpendingKey {
    // generates a random SpendingKey correspond with seed
    constructor(seed){
        var spendingKey = common.HashBytesToBytes(seed);

        // check whether spending key is less than curve.Params.N
        while (new common.BigInt(spendingKey, 10, 'be').gt(ec.Curve.n)) {
            spendingKey = common.HashBytesToBytes(spendingKey);
        }

        this.SpendingKey = spendingKey;
        return this;
    }
}

class PublicKey {
    // computes an public key corresponding with spendingKey
    constructor(spendingKey){
        var pk = ec.Curve.g.mul(new common.BigInt(spendingKey, 10, 'be'));

        this.PublicKey = ec.Compress(pk);
        return this;
    }

    GetSize(){
        return this.PublicKey.length;
    }
}

function TestKey(){
    var sk = new SpendingKey([123]);
    console.log("Spending key : ", sk.SpendingKey);

    var pk = new PublicKey(sk.SpendingKey);
    console.log("Public key : ", pk.PublicKey);
}

TestKey();


// var a = new common.BigInt([19], 10, 'be')

// console.log('a: ', a.toArray())
// console.log('b: ', b.toNumber())
// console.log('res: ', a.gt(b))

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


