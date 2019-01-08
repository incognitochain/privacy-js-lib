const SK      = 0x00;
const VALUE   = 0x01;
const SND     = 0x02;
const SHARDID = 0x03;
const RAND    = 0x04;
const FULL    = 0x05;
const PaymentAddrSize = 66;
const TransmissionKeySize = 33;
const PublicKeySize = 33;
const CompressPointSize = 33;
const BigIntSize = 32;
const MaxValue = 18446744073709551616;
const MaxEXP = 64;

const EncryptedRandomnessSize = 48; //bytes
const EncryptedSymKeySize = 66; //bytes

const HashSize = 32;// bytes

const CMRingSize    = 8; // 2^3
const CMRingSizeExp = 3;

module.exports = {PaymentAddrSize,
    TransmissionKeySize,
    PublicKeySize,
    CompressPointSize,
    BigIntSize,
    SK, VALUE, SND, SHARDID, RAND, FULL,
    EncryptedRandomnessSize, EncryptedSymKeySize,
    HashSize, CMRingSize, CMRingSizeExp};

