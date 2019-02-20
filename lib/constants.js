const SK = 0x00;
const VALUE = 0x01;
const SND = 0x02;
const SHARD_ID = 0x03;
const RAND = 0x04;
const FULL = 0x05;
const PAYMENT_ADDR_SIZE = 66;
const TRANSMISSION_KEY_SIZE = 33;
const PUBLIC_KEY_SIZE = 33;
const VIEWING_KEY_SIZE = 65;
const COMPRESS_POINT_SIZE = 33;
const BIG_INT_SIZE = 32;
const MaxValue = 18446744073709551616;
const MaxEXP = 64;

const EncryptedRandomnessSize = 48; //bytes
const EncryptedSymKeySize = 66; //bytes
const ElgamalCiphertextSize = 66;

const AESBlockSize = 16;

const PrivacyVersion = 0x00;

const HashSize = 32; // bytes

const CMRingSize = 8; // 2^3
const CMRingSizeExp = 3;

// size of zero knowledge proof corresponding one input
const OneOfManyProofSize = 716;
const SNPrivacyProofSize = 326;
const SNNoPrivacyProofSize = 196;

// size of zero knowledge proof corresponding one output
const ComZeroProofSize = 99;

const SHARD_NUMBER = 1;

const Uint64Size = 8; // bytes

const NumProofProperties = 14;

const PCCapacity = 5;

module.exports = {
    PAYMENT_ADDR_SIZE,
    TRANSMISSION_KEY_SIZE,
    PUBLIC_KEY_SIZE,
    VIEWING_KEY_SIZE,
    COMPRESS_POINT_SIZE,
    BIG_INT_SIZE,
    PCCapacity,
    SK,
    VALUE,
    SND,
    SHARD_ID,
    RAND,
    FULL,
    EncryptedRandomnessSize,
    EncryptedSymKeySize,
    HashSize,
    CMRingSize,
    CMRingSizeExp,
    MaxEXP,
    MaxValue,
    OneOfManyProofSize,
    SNPrivacyProofSize,
    SNNoPrivacyProofSize,
    ComZeroProofSize,
    SHARD_NUMBER,
    Uint64Size,
    NumProofProperties,
    ElgamalCiphertextSize,
    AESBlockSize,
    PrivacyVersion
};