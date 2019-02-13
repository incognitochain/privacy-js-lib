var common = require("./common");
var constants = require("./constants");

function RandBytes(n = constants.BigIntSize) {
    var b = new Uint8Array(n);
    for (var i = 0; i < n; i++) {
        b[i] = Math.floor(Math.random() * 256);
    }
    return b
}

function RandScalar(n = constants.BigIntSize) {
    var randbytes = RandBytes(n);
    // var number = new Int8Array(randbytes)
    // console.log(randbytes)
    //console.log(randbytes.length)
    var randNum = new common.BigInt(randbytes, 10, "be");
    var curveDeg = new common.Elliptic('p256').n;
    if (randNum.cmp(curveDeg) === -1) {
        // return randNum.toString(10, "")
        return randNum
    }
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
    var newNum = new common.BigInt(n);
    return newNum.toArray("be", 2);
    // return bytes array of length 2 in decimal
}

function ByteArrToInt(bytesArr) {
    var num = new common.BigInt(bytesArr, 16, "be");
    return parseInt(num.toString(10));
}

function stringToBytes(str) {
    var ch, st, re = [];
    for (var i = 0; i < str.length; i++) {
        ch = str.charCodeAt(i);  // get char
        st = [];                 // set up "stack"
        do {
            st.push(ch & 0xFF);  // push byte to stack
            ch = ch >> 8;          // shift value down by 1 byte
        }
        while (ch);
        // add stack contents to result
        // done because chars have "wrong" endianness
        re = re.concat(st.reverse());
    }
    // return an array of bytes
    return re;
}

function PAdd1Div4(p) {
    // return bigInt
    var res = new common.BigInt("0", 10);
    res = res.add(p);
    res = res.add(new common.BigInt("1", 10));
    res = res.div(new common.BigInt("4", 10));
    return res
}

function paddedAppend(size, dst, src) {
    // size: uint
    // dst,src: byte array
    for (var i = 0; i < size - src.length; i++) {
        dst = dst.concat(["0"]);
    }
    dst = dst.concat(src);
    return dst;
}

// generateChallengeFromPoint get hash of n points in G append with input values
// return sha256(G[0]||G[1]||...||G[CM_CAPACITY-1]||<values>)
// G[i] is list of all generator point of Curve
function generateChallengeFromPoint(listPoints) {
    var compsize = listPoints[0].compress().length;
    var bytesHash = new Uint8Array(listPoints.length * compsize);
    for (var i = 0; i < listPoints.length; i++) {
        bytesHash.set(listPoints[i].compress(), i * compsize);
    }
    return new common.BigInt(common.HashBytesToBytes(bytesHash), 10);
}



function generateChallenge(values) {
    let bytes = PedCom.G[0].compress();
    for (let i = 1; i < PedCom.G.length; i++) {
        bytes.concat(PedCom.G[i].compress());
    }
    for (let i = 0; i < values.length; i++) {
        bytes.concat(values[i])
    }
    let hash = common.HashBytesToBytes(bytes);
    let res = new common.BigInt(bytes, 10);
    res.umod(P256.n);
    return res
}
// Todo:
// CheckDuplicateBigIntArray returns true if there are at least 2 elements in an array have same values
function checkDuplicateBigIntArray(arr) {
    return false;
}

function ConvertIntToBinary(num, n){
    let bitString = num.toString(2);
    let bytes = new Uint8Array(n);
    for (let i = 0; i <= bitString.length; i++) {
        let b = bitString.charCodeAt(i);
        bytes[n - bitString.length + i] = b - 48
    }
    return bytes
}

module.exports = {
    RandScalar, AddPaddingBigInt, ByteArrToInt, IntToByteArr, IsPowerOfTwo, paddedAppend,
    RandBytes, PAdd1Div4, joinArray, generateChallengeFromPoint, checkDuplicateBigIntArray, stringToBytes,
    ConvertIntToBinary, generateChallenge
};
function TestUtil(){
    let res = ConvertIntToBinary(10, 10);
    console.log(res);
}



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
// x = 4
// y = ConvertIntToBinary(x,16)
//
// console.log(y);




