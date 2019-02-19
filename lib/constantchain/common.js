const constants = require('../constants')

/**
 * @return {number}
 */
function GetShardIDFromLastByte(lastByte) {
    return lastByte % constants.SHARD_NUMBER
}

module.exports = {GetShardIDFromLastByte};