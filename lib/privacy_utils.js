let common = require("./common");
let constants = require("./constants");
function RandBytes(n = constants.BigIntSize) {
    let b = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
        b[i] = Math.floor(Math.random() * 256);
    }
    return b
}

function RandScalar(n = constants.BigIntSize) {
    let randNum = new common.BigInt("0");
    let curveDeg = new common.Elliptic('p256').n;
    do {
        let randbytes = RandBytes(n);
        randNum = new common.BigInt(randbytes, 10, "be");
    } while (randNum.cmp(curveDeg) !== -1);
    return randNum
}
/**
 * @return {boolean}
 */
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
    let newNum = new common.BigInt(n);
    let bytes = newNum.toArray("be");
    if (bytes.length > 2){
        return []
    }
    else return newNum.toArray("be",2);

}

function ByteArrToInt(bytesArr) {
    let num = new common.BigInt(bytesArr, 16, "be");
    return parseInt(num.toString(10));
}

// maybe this function is not used in JS
function paddedAppend(size, dst, src) {
    // size: uint
    // dst,src: byte array
    for (let i = 0; i < size - src.length; i++) {
        dst = dst.concat(["0"]);
        
    }
    dst = dst.concat(src);
    return dst;
}

// CheckDuplicateBigIntArray returns true if there are at least 2 elements in an array have same values
function checkDuplicateBigIntArray(arr) {
    let set = new Set(arr);
    if (set.size !==arr.length){
        return true;
    }
    return false;
}

function ConvertIntToBinary(num, n){
    let bytes = new Uint8Array(n);
    for (let i = 0; i < n; i++){
        bytes[i] = num & 1;
        num >>= 1;
    }

    return bytes
}

module.exports = {
    RandScalar, AddPaddingBigInt, ByteArrToInt, IntToByteArr, IsPowerOfTwo, paddedAppend,
    RandBytes, checkDuplicateBigIntArray, ConvertIntToBinary
};

function TestUtil(){
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

    // let padd1div4 = PAdd1Div4(new common.BigInt(num));
    // console.log('res : ', padd1div4.toArray());
}
// TestUtil();


// Usage
// function main() {
//     // x = new PrivacyUtils()
//     // a = x.RandScalar(31)
//     // console.log(x.AddPaddingBigInt(a,32))
//     bytesArr = x.IntToByteArr(150)
//     console.log(bytesArr)
//     k = x.ByteArrToInt(bytesArr)
//     console.log(k)
//
//     p = new common.BigInt("16",10)
//     console.log(PAdd1Div4(p))
// }




