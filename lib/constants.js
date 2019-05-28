const SK = 0x00;
const VALUE = 0x01;
const SND = 0x02;
const SHARD_ID = 0x03;
const RAND = 0x04;
const FULL = 0x05;

const COMPRESS_POINT_SIZE = 33;
const BIG_INT_SIZE = 32;
const MAX_VALUE = 18446744073709551616;
const MAX_EXP = 64;

const CM_RING_SIZE = 8; // 2^3
const CM_RING_SIZE_EXP = 3;

// size of zero knowledge proof corresponding one input
const ONE_OF_MANY_PROOF_SIZE = 716;
const SN_PRIVACY_PROOF_SIZE = 326;
const SN_NO_PRIVACY_PROOF_SIZE = 196;

const UINT64_SIZE = 8; // bytes

const PC_CAPACITY = 5;

module.exports = {
    COMPRESS_POINT_SIZE,
    BIG_INT_SIZE,
    PC_CAPACITY,
    SK,
    VALUE,
    SND,
    SHARD_ID,
    RAND,
    FULL,
    CM_RING_SIZE,
    CM_RING_SIZE_EXP,
    MAX_EXP,
    MAX_VALUE,
    ONE_OF_MANY_PROOF_SIZE,
    SN_PRIVACY_PROOF_SIZE,
    SN_NO_PRIVACY_PROOF_SIZE,
    UINT64_SIZE,
};