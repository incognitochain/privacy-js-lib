var common = require("./common");
function RandBytes(n) {
    var b = new Uint8Array(n)
    for (var i = 0; i < n; i++) {
        b[i] = Math.floor(Math.random() * 256);
    }
    return b
}
function RandInt(n) {
    var randbytes = this.RandBytes(n)
    // var number = new Int8Array(randbytes)
    // console.log(randbytes)
    console.log(randbytes.length)
    var randNum = new common.BigInt(randbytes,10,"be")
    var curveDeg = new common.Elliptic('p256').n
    if (randNum.cmp(curveDeg)==-1) {
        // return randNum.toString(10, "")
        return randNum
    }
}
function IsPowerOfTwo(n) {
    if (n<2) {
        return false
    }
    while (n>2){
        if (n%2===0){
            n = n>>1;
        }
        else {
            return false
        }
    }
    return true
}

function AddPaddingBigInt(numInt, fixedSize) {
    //numInt: type BigInt
    //fixedSize: type int
    return numInt.toBuffer("be",fixedSize)
}

function IntToByteArr(n) {
    var newNum = new common.BigInt(n.toString(10),10)
    return newNum.toBuffer("be", 8)
    // return 8-byte array in hexa
}

function ByteArrToInt(bytesArr) {
    var num = new common.BigInt(bytesArr,16,"be")
    return num.toString(10,"")
}

function PAdd1Div4(p) {
    // return bigInt
    var res = new common.BigInt("0",10)
    res = res.add(p)
    res = res.add(new common.BigInt("1",10))
    res = res.div(new common.BigInt("4",10))
    return res
}

function paddedAppend(size, dst, src){
    // size: uint
    // dst,src: byte array
    for (var i=0;i<size - src.length;i++){
        dst = dst.concat(["0"]);
    }
    dst = dst.concat(src)
    return dst;
}

// generateChallengeFromPoint get hash of n points in G append with input values
// return sha256(G[0]||G[1]||...||G[CM_CAPACITY-1]||<values>)
// G[i] is list of all generator point of Curve
function generateChallengeFromPoint(listPoints){
    var compsize = listPoints[0].compress().length;
    var bytesHash = new Uint8Array(listPoints.length*compsize);
    for (var i = 0; i<listPoints.length; i++) {
        bytesHash.set(listPoints[i].compress(), i*compsize);
    }
    return new common.BigInt(common.HashBytesToBytes(bytesHash),10);
}
module.exports = {RandInt, AddPaddingBigInt, ByteArrToInt, IntToByteArr , IsPowerOfTwo, paddedAppend, RandBytes, PAdd1Div4, generateChallengeFromPoint}
// Usage
function main() {
//     // x = new PrivacyUtils()
//     // a = x.RandInt(31)
//     // console.log(x.AddPaddingBigInt(a,32))
//     bytesArr = x.IntToByteArr(150)
//     console.log(bytesArr)
//     k = x.ByteArrToInt(bytesArr)
//     console.log(k)
//
//     p = new common.BigInt("16",10)
//     console.log(PAdd1Div4(p))
}
