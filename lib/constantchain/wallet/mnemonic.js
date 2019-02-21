const NewWordList = require("./wordlist").NewWordList;
const randomBytes = require("random-bytes")

let utils = require('../../privacy_utils');
let BigInt = require('bn.js');
let pbkdf2 = require('pbkdf2')

// Some bitwise operands for working with big.Ints
const last11BitsMask = new BigInt(2047)
const rightShift11BitsDivider = new BigInt(2048)
const bigOne = new BigInt(1)
const bigTwo = new BigInt(2)

// used to isolate the checksum bits from the Entropy+checksum byte array
let wordLengthChecksumMasksMapping = {
  12: new BigInt(15),
  15: new BigInt(31),
  18: new BigInt(63),
  21: new BigInt(127),
  24: new BigInt(255),
}

// used to use only the desired x of 8 available checksum bits.
// 256 bit (word length 24) requires all 8 bits of the checksum,
// and thus no shifting is needed for it (we would get a divByZero crash if we did)
let wordLengthChecksumShiftMapping = {
  12: new BigInt(15),
  15: new BigInt(8),
  18: new BigInt(4),
}

let wordList = [];
let wordMap = {};

let ErrEntropyLengthInvalid = new Error("entropy length must be [128, 256] and a multiple of 32")

function init() {
  var list = NewWordList("english")
  wordList = list
  for (let i = 0; i < wordList.length; i++) {
    wordMap[wordList[i]] = i;
  }
}

function validateEntropyBitSize(bitSize) {
  try {
    if ((bitSize % 32) != 0 || bitSize < 128 || bitSize > 256) {
      return ErrEntropyLengthInvalid
    }
  } catch (ex) {
    return ex
  }
  return null
}

function randomDataSet(dataSetSize, minValue, maxValue) {
  return new Array(dataSetSize).fill(0).map(function (n) {
    return Math.random() * (maxValue - minValue) + minValue;
  });
}

class MnemonicGenerator {
  constructor() {
    init();
  }

  // NewEntropy will create random Entropy bytes
  // so long as the requested size bitSize is an appropriate size.
  //
  // bitSize has to be a multiple 32 and be within the inclusive range of {128, 256}
  NewEntropy(bitSize) {
    var err = validateEntropyBitSize(bitSize)
    if (err != null) {
      throw err;
    }

    // create bytes array for Entropy from bitsize
    // random byte
    var entropy = randomBytes.sync(bitSize / 8);
    return entropy;
  }

  // NewMnemonic will return a string consisting of the Mnemonic words for
  // the given Entropy.
  // If the provide Entropy is invalid, an error will be returned.
  NewMnemonic(entropy) {
    let entropyBitLength = entropy.length * 8;
    let checksumBitLength = entropyBitLength / 32
    let sentenceLength = (entropyBitLength + checksumBitLength) / 11

    let err = validateEntropyBitSize(entropyBitLength)
    if (err != null) {
      throw err;
    }

    // Add checksum to Entropy
    entropy = this.addChecksum(entropy)

    // Break Entropy up into sentenceLength chunks of 11 bits
    // For each word AND mask the rightmost 11 bits and find the word at that index
    // Then bitshift Entropy 11 bits right and repeat
    // Add to the last empty slot so we can work with LSBs instead of MSB

    // Entropy as an int so we can bitmask without worrying about bytes slices
    let entropyInt = new BigInt.BN(entropy);

    // Slice to hold words in
    let words = [];

    // Throw away big int for AND masking
    let word = new BigInt(0);

    for (let i = sentenceLength - 1; i >= 0; i--) {
      // Get 11 right most bits and bitshift 11 to the right for next time
      word = entropyInt.and(last11BitsMask);
      console.log(word.toArray());
      entropyInt = entropyInt.div(rightShift11BitsDivider);

      // Get the bytes representing the 11 bits as a 2 byte slice
      let wordBytes = this.padByteSlice(word.toArray(), 2);

      // Convert bytes to an index and add that word to the list
      let index = new BigInt.BN(wordBytes)
      words[i] = wordList[index]
    }

    return words.join(" ");
  }

  padByteSlice(slice, lenght) {
    let offset = lenght - slice.length
    if (offset <= 0) {
      return slice
    }
    let newSlice = slice.slice(offset);
    return newSlice
  }

  // Appends to data the first (len(data) / 32)bits of the result of sha256(data)
  // Currently only supports data up to 32 bytes
  addChecksum(data) {
    var hash = this.computeChecksum(data)
    // Get first byte of sha256
    var firstChecksumByte = hash[0]

    // len() is in bytes so we divide by 4
    var checksumBitLength = data.length / 4

    // For each bit of check sum we want we shift the data one the left
    // and then set the (new) right most bit equal to checksum bit at that index
    // staring from the left
    var dataBigInt = new BigInt.BN(data)

    for (var i = 0; i < checksumBitLength; i++) {
      dataBigInt = dataBigInt.mul(bigTwo)
    }

    // Set rightmost bit if leftmost checksum bit is set
    if (firstChecksumByte & (1 << (7 - i)) > 0) {
      dataBigInt = dataBigInt.or(bigOne)
    }
    return dataBigInt.toArray("be")
  }

  computeChecksum(data) {
    return utils.hashBytesToBytes(data)
  }

  NewSeed(mnemonic, password) {
    return pbkdf2.pbkdf2Sync(mnemonic, "Mnemonic" + password, 2048, 64, "sha512")
  }
}

module.exports = {MnemonicGenerator};
