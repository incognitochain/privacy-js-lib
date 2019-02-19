let base58 = require('../../base58');

function addChecksumToBytes(data) {
    let checksum = base58.checkSumFirst4Bytes(data);

    let res = new Uint8Array(data.length + 4);
    res.set(data, 0);
    res.set(checksum, data.length);
    return res;
}

module.exports = {addChecksumToBytes};