const keyset = require('../../keyset');
const key = require('../../key');
const constants = require('./constants');
const utils = require('./utils');
const privacyConstanst = require('../../constants');
const base58 = require('../../base58');


class KeyWallet{
    constructor(){
       this.Depth = 0;              // 1 byte
       this.ChildNumber = new Uint8Array(4);       // 4 bytes
       this.ChainCode = new Uint8Array(32);         // 32 bytes
       this.KeySet = new keyset.KeySet();
    }
    fromSpendingKey(spendingKey){
        this.Depth = 0;              // 1 byte
        this.ChildNumber = new Uint8Array(4);       // 4 bytes
        this.ChainCode = new Uint8Array(32);         // 32 bytes
        this.KeySet = new keyset.KeySet().fromSpendingKey(spendingKey);
        return this;
    }

    // Serialize a KeySet to a 78 byte byte slice
    serialize(keyType) {
        // Write fields to buffer in order
        let keyBytes;

        if (keyType === constants.PriKeyType) {
            keyBytes = new Uint8Array(constants.PriKeySerializeSize);
            let offset = 0;
            keyBytes.set([keyType], offset);
            offset += 1;

            keyBytes.set([this.Depth], offset);
            offset += 1;

            keyBytes.set(this.ChildNumber, offset);
            offset += 4;

            keyBytes.set(this.ChainCode, offset);
            offset += 32;

            keyBytes.set([this.KeySet.PrivateKey.length], offset);
            offset += 1;
            keyBytes.set(this.KeySet.PrivateKey, offset);
            console.log("Offset: ", offset);

        } else if (keyType === constants.PaymentAddressType) {
            keyBytes = new Uint8Array(constants.PaymentAddrSerializeSize);
            let offset = 0;
            keyBytes.set([keyType], offset);
            offset += 1;

            keyBytes.set([this.KeySet.PaymentAddress.PublicKey.length], offset);
            offset += 1;
            keyBytes.set(this.KeySet.PaymentAddress.PublicKey, offset);
            offset += privacyConstanst.CompressPointSize;

            keyBytes.set([this.KeySet.PaymentAddress.TransmisionKey.length], offset);
            offset += 1;
            keyBytes.set(this.KeySet.PaymentAddress.TransmisionKey, offset);

        } else if (keyType === constants.ReadonlyKeyType) {
            keyBytes = new Uint8Array(constants.ReadonlyKeySerializeSize);
            let offset = 0;
            keyBytes.set([keyType], offset);
            offset += 1;

            keyBytes.set([this.KeySet.ReadonlyKey.PublicKey.length], offset);
            offset += 1;
            keyBytes.set(this.KeySet.ReadonlyKey.PublicKey, offset);
            offset += privacyConstanst.CompressPointSize;

            keyBytes.set([this.KeySet.ReadonlyKey.ReceivingKey.length], offset);
            offset += 1;
            keyBytes.set(this.KeySet.ReadonlyKey.ReceivingKey, offset);
        }

        // Append key bytes to the standard doublesha256 checksum
        return utils.addChecksumToBytes(keyBytes);
    }

    base58CheckSerialize(keyType){
        let serializedKey = this.serialize(keyType);
        return base58.checkEncode(serializedKey, 0x00);
    }

    static deserialize(bytes){
        let key = new KeyWallet();

        // get key type
        let keyType = bytes[0];

        if (keyType === constants.PriKeyType) {
            key.Depth = bytes[1];
            key.ChildNumber = bytes.slice(2,6);
            key.ChainCode = bytes.slice(6,38);
            let keyLength = bytes[38];

            key.KeySet.PrivateKey = bytes.slice(39, 39 + keyLength);

        } else if (keyType === constants.PaymentAddressType) {
            let PublicKeyLength = bytes[1];
            key.KeySet.PaymentAddress.Pk = bytes.slice(2, 2+PublicKeyLength);

            let TransmisionKeyLength = bytes[PublicKeyLength+2];
            key.KeySet.PaymentAddress.Tk = bytes.slice(PublicKeyLength + 3, PublicKeyLength + 3 + TransmisionKeyLength);
        } else if (keyType === constants.ReadonlyKeyType) {

            let PublicKeyLength = bytes[1];
            key.KeySet.PaymentAddress.Pk = bytes.slice(2, 2+PublicKeyLength);

            let ReceivingKeyLength = bytes[PublicKeyLength+2];
            key.KeySet.PaymentAddress.ReceivingKey = bytes.slice(PublicKeyLength + 3, PublicKeyLength + 3 + ReceivingKeyLength);
        }

        // validate checksum
        let cs1  = base58.checkSumFirst4Bytes(bytes.slice(0, bytes.length - 4));
        let cs2 = bytes.slice(bytes.length-4);

        if (cs1.length !== cs2.length){
            throw error("Checksum wrong!!!")
        } else{
            for (let i=0; i<cs1.length; i++){
                if (cs1[i] !== cs2[i]) {
                    throw error("Checksum wrong!!!")
                }
            }
        }
        return key;
    }

    static base58CheckDeserialize(str){
        let bytes = base58.checkDecode(str).bytesDecoded;
        return this.deserialize(bytes);
    }

    // static getKeySet(privateKeyWalletStr) {
    //     // deserialize to crate keywallet object which contain private key
    //     let keyWallet = this.base58CheckDeserialize(privateKeyWalletStr);
    //
    //     // fill paymentaddress and readonly key with privatekey
    //     keyWallet.KeySet.importFromPrivateKey(keyWallet.KeySet.PrivateKey);
    //     return keyWallet.KeySet;
    // }
}


function TestKeyWallet() {

    let spendingKey = key.GenerateSpendingKey([123]);
    console.log("Spending key: ", spendingKey.join(" , "));
    let keyWallet = new KeyWallet().fromSpendingKey(spendingKey);

    console.log("Key wallet : ", keyWallet);
    let keySerial = keyWallet.base58CheckSerialize(constants.PriKeyType);
    console.log("Key serial: ", keySerial);

    let keyDeserialize = KeyWallet.base58CheckDeserialize(keySerial);
    console.log("Key deserialize :", keyDeserialize.KeySet.PaymentAddress);

    let keySet = KeyWallet.getKeySet(keySerial);
    console.log("Key set after get key set: ", keySet);

}

// TestKeyWallet();


module.exports = {KeyWallet};