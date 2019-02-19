const axios = require('axios');


async function requestAPI(data = {}, method = "GET", url = "http://localhost:9334", options = {}) {
    if (Object.keys(data).length <= 0) {
        return
    }

    return await axios({
        method: method,
        url: url,
        data: data,
        ...options,
    });
}

module.exports ={requestAPI};