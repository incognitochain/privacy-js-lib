let Elliptic = require('elliptic').ec;
let BigInt = require('bn.js');
let P256 = new Elliptic('p256');
let constants = require('./constants');
const sjcl = require('./sjcl/sjcl');
const {SHA3} = require('sha3');

function randBytes(n = constants.BIG_INT_SIZE) {
  try {
    let paranoiaLvl = 6; //256bit entropy https://github.com/bitwiseshiftleft/sjcl/issues/156
    let wordLength = (n >> 2) + 1;
    let words = sjcl.random.randomWords(wordLength, paranoiaLvl);
    res = sjcl.codec.bytes.fromBits(words);
    return res.slice(0, n);
  } catch (e) {
    console.log(e);
    if (Utility.RandomBytesFunc) {
      return Utility.RandomBytesFunc(n);
    }
    throw e;
  }
}

function randScalar(n = constants.BIG_INT_SIZE) {
  let randNum = new BigInt("0");
  let curveDeg = P256.n;
  do {
    let randbytes = randBytes(n);
    randNum = new BigInt(randbytes, 10, "be");
  } while (randNum.cmp(curveDeg) !== -1);
  return randNum;
}

function IsPowerOfTwo(n) {
  if (n < 2) {
    return false;
  }
  while (n > 2) {
    if (n % 2 === 0) {
      n = n >> 1;
    } else {
      return false;
    }
  }
  return true;
}

function addPaddingBigInt(numInt, fixedSize) {
  //numInt: type BigInt
  //fixedSize: type int
  return numInt.toArray("be", fixedSize);
}

function intToByteArr(n) {
  // return bytes array of length 2 in decimal
  let newNum = new BigInt(n);
  let bytes = newNum.toArray("be");
  if (bytes.length > 2) {
    return []
  } else return newNum.toArray("be", 2);

}

function byteArrToInt(bytesArr) {
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

function convertIntToBinary(num, n) {
  let bytes = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    bytes[i] = num & 1;
    num >>= 1;
  }
  return bytes;
}

function hashBytesToBytes(data) {
  return sjcl.codec.bytes.fromBits(sjcl.hash.sha256.hash(sjcl.codec.bytes.toBits(data)));
}

function hashSha3BytesToBytes(data) {
  data = new Uint8Array(data)
  let temp = new Buffer(data);
  let result = new SHA3(256).update(temp);
  result = result.digest()
  return [...new Uint8Array(result)];
}

function doubleHashBytesToBytes(data) {
  return sjcl.codec.bytes.fromBits(sjcl.hash.sha256.hash(sjcl.hash.sha256.hash(sjcl.codec.bytes.toBits(data))))
}

function convertUint8ArrayToArray(data) {
  return [...data];
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

class Utility {
  static RandomBytesFunc = null;
}

module.exports = {
  hashBytesToBytes,
  doubleHashBytesToBytes,
  randScalar,
  addPaddingBigInt,
  intToByteArr,
  randBytes,
  checkDuplicateBigIntArray,
  convertIntToBinary,
  convertUint8ArrayToArray,
  stringToBytes,
  hashSha3BytesToBytes,
};

