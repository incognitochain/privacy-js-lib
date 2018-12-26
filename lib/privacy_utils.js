class PrivacyUtils {
    RandBytes(n) {
        var b = new ArrayBuffer(n)
        for (var i = 0; i < n; i++) {
            b[i] = Math.floor(Math.random() * 256);
        }
        return b
    }


    RandInt() {
        // for {
        //     bytes := make([]byte, BigIntSize)
        //     for i := 0; i < BigIntSize; i++ {
        //     bytes[i] = RandByte()
        // }
        // randNum := new(big.Int).SetBytes(bytes)
        // if TestRandInt(randNum) && randNum.Cmp(Curve.Params().N) == -1 {
        //     return randNum
        // }
    }

    IsPowerOfTwo(n) {

    }

    AddPaddingBigInt(numInt, fixedSize) {

        // return bytearray
    }

    IntToByteArr(n) {
        // return bytearray
    }

    ByteArrToInt(bytesArr) {
        // return int
    }


    isOdd(a) {
        // return boolean
    }

    PAdd1Div4(p) {
        // return bigInt
    }

    paddedAppend(size, dst, src){
        // size: uint
        // dst,src: byte array
    }

}
x = new PrivacyUtils()
console.log(x)