let BigInt = require('bn.js');
let constants = require('./constants');
const sjcl = require('sjcl');

function RandBytes(n = constants.BigIntSize) {
    let paranoiaLvl = 6; //256bit entropy https://github.com/bitwiseshiftleft/sjcl/issues/156 
    let wordLength = Math.floor(n/4) + 1;
    res = sjcl.codec.bytes.fromBits(sjcl.random.randomWords(wordLength,paranoiaLvl));
    return res.slice(0,n);
}

function RandScalar(n = constants.BigIntSize) {
    let randNum = new BigInt("0");
    let curveDeg = new common.Elliptic('p256').n;
    do {
        let randbytes = RandBytes(n);
        randNum = new BigInt(randbytes, 10, "be");
    } while (randNum.cmp(curveDeg) !== -1);
    return randNum
}

function IsPowerOfTwo(n) {
    if (n < 2) {
        return false
    }
    while (n > 2) {
        if (n % 2 === 0) {
            n = n >> 1;
        } else {
            return false
        }
    }
    return true
}

function AddPaddingBigInt(numInt, fixedSize) {
    //numInt: type BigInt
    //fixedSize: type int
    return numInt.toArray("be", fixedSize)
}

function IntToByteArr(n) {
    // return bytes array of length 2 in decimal
    let newNum = new BigInt(n);
    let bytes = newNum.toArray("be");
    if (bytes.length > 2) {
        return []
    } else return newNum.toArray("be", 2);

}

function ByteArrToInt(bytesArr) {
    let num = new BigInt(bytesArr, 16, "be");
    return parseInt(num.toString(10));
}
// CheckDuplicateBigIntArray returns true if there are at least 2 elements in an array have same values
function checkDuplicateBigIntArray(arr) {
    let set = new Set(arr);
    if (set.size !== arr.length) {
        return true;
    }
    return false;
}

function ConvertIntToBinary(num, n) {
    let bytes = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
        bytes[i] = num & 1;
        num >>= 1;
    }
    return bytes
}

function HashBytesToBytes(data) {
    return sjcl.codec.bytes.fromBits(sjcl.hash.sha256.hash(sjcl.codec.bytes.toBits(data)));
}

function DoubleHashBytesToBytes(data) {
    return sjcl.codec.bytes.fromBits(sjcl.hash.sha256.hash(sjcl.hash.sha256.hash(sjcl.codec.bytes.toBits(data))))
}

module.exports = {
    HashBytesToBytes,
    DoubleHashBytesToBytes,
    RandScalar,
    AddPaddingBigInt,
    ByteArrToInt,
    IntToByteArr,
    IsPowerOfTwo,
    RandBytes,
    checkDuplicateBigIntArray,
    ConvertIntToBinary
};

function TestUtil() {
    let res = ConvertIntToBinary(11, 10);
    console.log('res: ', res);
    console.log(res[0]);

    let a = RandBytes(2);
    console.log(a);

    let num = 100;
    let numByte = IntToByteArr(num);
    let num2 = ByteArrToInt(numByte);

    console.log('numByte: ', numByte);
    console.log('num2: ', num2);
}
// TestUtil();