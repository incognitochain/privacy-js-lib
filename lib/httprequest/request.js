const axios = require('axios');


// http://192.168.0.39:9334
async function requestAPI(data = {}, method = "POST", url = "http://localhost:9334", options = {}) {
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
