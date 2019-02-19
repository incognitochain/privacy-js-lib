let key = require('./key');

class KeySet {
    constructor(){
        this.PrivateKey = [];
        this.PaymentAddress = new key.PaymentAddress();
        this.ReadonlyKey = new key.ViewingKey();
    }
    importFromPrivateKey(privateKey){
        this.PrivateKey = privateKey;
        this.PaymentAddress = new key.PaymentAddress().fromSpendingKey(privateKey);
        this.ReadonlyKey = new key.ViewingKey().fromSpendingKey(privateKey);
        return this;
    }
}

module.exports ={KeySet};