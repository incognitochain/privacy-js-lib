let key = require('./key');

class KeySet {
    constructor(){
        this.PrivateKey = [];
        this.PaymentAddress = new key.PaymentAddress();
        this.ReadonlyKey = new key.ViewingKey();
    }
    fromSpendingKey(spendingKey){
        this.PrivateKey = spendingKey;
        this.PaymentAddress = new key.PaymentAddress().fromSpendingKey(spendingKey);
        this.ReadonlyKey = new key.ViewingKey(spendingKey);
        return this;
    }
    importFromPrivateKey(privateKey){
        this.PrivateKey = privateKey;
        this.PaymentAddress = new key.PaymentAddress().fromSpendingKey(privateKey);
        this.ReadonlyKey = new key.ViewingKey().fromSpeningKey(privateKey);
    }
}

module.exports ={KeySet};