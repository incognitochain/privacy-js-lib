var common = require("./common");
class PrivacyUtils {
    constructor(){

    }
    RandBytes(n) {
        var b = new Uint8Array(n)
        for (var i = 0; i < n; i++) {
            b[i] = Math.floor(Math.random() * 256);
        }
        return b
    }
    RandInt(n) {
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
    IsPowerOfTwo(n) {
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

    AddPaddingBigInt(numInt, fixedSize) {
        //numInt: type BigInt
        //fixedSize: type int
       return numInt.toBuffer("be",fixedSize)
    }

    IntToByteArr(n) {
        var newNum = new common.BigInt(n.toString(10),10,)
        return newNum.toBuffer("be", 8)
        // return 8-byte array in hexa
    }

    ByteArrToInt(bytesArr) {
        var num = new common.BigInt(bytesArr,16,"be")
        return num.toString(10,"")
    }

    PAdd1Div4(p) {
        // return bigInt
        var res = new common.BigInt("0",10)
        res = res.add(p)
        res = res.add(new common.BigInt("1",10))
        res = res.div(new common.BigInt("4",10))
        return res
    }

    paddedAppend(size, dst, src){
        // size: uint
        // dst,src: byte array
        for (var i=0;i<size - src.length;i++){
            dst = dst.concat(["0"]);
        }
        dst = dst.concat(src)
        return dst
    }
}

// Usage
function main()
{
    x = new PrivacyUtils()
    // a = x.RandInt(31)
    // console.log(x.AddPaddingBigInt(a,32))
    bytesArr = x.IntToByteArr(150)
    console.log(bytesArr)
    k = x.ByteArrToInt(bytesArr)
    console.log(k)

    p = new common.BigInt("16",10)
    console.log(x.PAdd1Div4(p))

}
main()