var common = require('./../common');
var ec = require('./../ec.js');
var constants = require('./../constants');
var key = require('./../key');
var utils = require('./../privacy_utils');
var zkp = require('./../zkps/zkp');

const TxVersion = 1;
const ConstantID = new Uint8Array(32);
ConstantID[0] = 4;

class Tx{
    constructor(){
        this.Version = 0;
        this.Type = "";
        this.LockTime = 0;
        this.Fee = 0;

        this.SigPubKey = new Uint8Array(0);
        this.Sig = new Uint8Array(0);
        this.Proof = new zkp.PaymentProof();

        this.PubKeyLastByte = 0x00;
        this.Metadata = new Uint8Array(0);

        this.sigPrivKey = new Uint8Array(0);
    }

    Init(senderSK, paymentInfo, inputCoins, fee, hasPrivacy, db, tokenID, metaData){
        this.Version = TxVersion;

        if (tokenID.length == 0){
            tokenID = ConstantID;
        }

        if (tx.LockTime == 0){
            tx.LockTime = new Date().getTime();
        }

        senderPublicKey




    }



}
