const constants = require('../constants')

/**
 * @return {number}
 */
function getShardIDFromLastByte(lastByte) {
  return lastByte % constants.SHARD_NUMBER
}

module.exports = {getShardIDFromLastByte};