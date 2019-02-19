let BigInt = require('bn.js');
function knapsack(value, target) {
    let n = value.length;
    let res = new Array(n);
    let K = new Array(n + 1);
    let i = 0;
    let w = 0;
    for (i = 0; i <= n; i++) {
        res[i] = false;
        let rowI = new Array(target + 1);
        for (w = 0; w <= target; w++) {
            rowI[w] = ((i * w) == 0) ? (0) : ((value[i - 1] <= w) ? (((1 + K[i - 1][w - value[i - 1]]) < K[i - 1][w]) ? (K[i - 1][w]) : (1 + K[i - 1][w - value[i - 1]])) : (K[i - 1][w]));
        }
        K[i] = rowI;
    }
    i = n;
    w = target;
    while ((i * w) > 0) {
        if (K[i][w] != K[i - 1][w]) {
            res[i - 1] = true;
            w -= value[i - 1];
        }
        i--;
    }
    return res;
}

function greedy(inputCoins, target) {
    let sum = new BigInt(0);
    let i=0;
    for (; sum.cmp(target)<0;i++){
        sum=sum.add(inputCoins[i].CoinDetails.Value);
    }
    return i-1;
}

module.exports = {
    knapsack,
    greedy
};