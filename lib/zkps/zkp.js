class PaymentWitness{
    constructor(){
        return this;
    }
    init(hasPrivacy, senderSK, inputCoins, outputCoins, pkLastByteSender, commitmentProving, commitmentIndexs, myCommitmentIndexs, fee){
        return this;
    }
    prove(hasPrivacy){
        return new PaymentProof();
    }
}

class PaymentProof{
    constructor(){
        return this;
    }
    toBytes(){
        return [];
    }
}

module.exports = {PaymentWitness, PaymentProof};