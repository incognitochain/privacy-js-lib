const PriKeyType = require('constants');
const KeyWallet = require("./hdwallet").KeyWallet;
const NewMasterKey = require("./hdwallet").NewMasterKey;
const MnemonicGenerator = require("./mnemonic").MnemonicGenerator;
let CryptoJS = require("crypto-js");
let JSON = require("circular-json")
const keyset = require('../../keyset');

class AccountWallet {
  constructor() {
    this.Name = "";
    this.Key = new KeyWallet();
    this.Child = [];
    this.IsImport = false;
  }
}

class Wallet {
  constructor() {
    this.Seed = [];
    this.Entropy = [];
    this.PassPhrase = "";
    this.Mnemonic = "";
    this.MasterAccount = new AccountWallet();
    this.Name = "";
    this.Storage = null;
  }

  Init(passPhrase, numOfAccount, name, storage) {
    let mnemonicGen = new MnemonicGenerator();
    this.Name = name;
    this.Entropy = mnemonicGen.newEntropy(128);
    this.Mnemonic = mnemonicGen.newMnemonic(this.Entropy);
    this.Seed = mnemonicGen.newSeed(this.Mnemonic, passPhrase);

    let masterKey = NewMasterKey(this.Seed);

    this.MasterAccount = new AccountWallet()
    this.MasterAccount.Key = masterKey;
    this.MasterAccount.Child = [];
    this.MasterAccount.Name = "master";

    if (numOfAccount == 0) {
      numOfAccount = 1;
    }

    for (let i = 0; i < numOfAccount; i++) {
      let childKey = this.MasterAccount.Key.NewChildKey(i);
      let account = new AccountWallet()
      account.Name = "AccountWallet " + i;
      account.Child = [];
      account.Key = childKey;
      this.MasterAccount.Child.push(account)
    }

    this.Storage = storage;
  }

  CreateNewAccount(accountName) {
    let newIndex = this.MasterAccount.Child.length;
    let childKey = this.MasterAccount.Key.NewChildKey(newIndex);
    if (accountName == "") {
      accountName = "AccountWallet " + newIndex;
    }
    let accountWallet = new AccountWallet()
    accountWallet.Key = childKey;
    accountWallet.Child = [];
    accountWallet.Name = accountName;

    this.MasterAccount.Child.push(accountWallet);
    this.Save(this.PassPhrase)

    return accountWallet;
  }

  ExportAccount(childIndex) {
    return this.MasterAccount.Child[childIndex].Key.base58CheckSerialize(PriKeyType);
  }

  RemoveAccount(privakeyStr, accountName, passPhrase) {
    if (passPhrase != this.PassPhrase) {
      throw new Error("Wrong passphrase")
    }
    for (let i = 0; i < this.MasterAccount.Child.length; i++) {
      let account = this.MasterAccount.Child[i]
      if (account.Key.base58CheckSerialize(PriKeyType) == privakeyStr) {
        this.MasterAccount.Child.splice(i);
        this.Save(this.PassPhrase)
        return
      }
    }
    throw new Error("Unexpected error")
  }

  ImportAccount(privakeyStr, accountName, passPhrase) {
    if (passPhrase != this.PassPhrase) {
      throw new Error("Wrong passphrase")
    }

    for (let i = 0; i < this.MasterAccount.Child.length; i++) {
      let account = this.MasterAccount.Child[i];
      if (account.Key.base58CheckSerialize(PriKeyType) == privakeyStr) {
        throw new Error("Existed account");
      }
      if (account.Name == accountName) {
        throw new Error("Existed account");
      }
    }

    let keyWallet = KeyWallet.base58CheckDeserialize(privakeyStr)
    keyWallet.KeySet.importFromPrivateKey(keyWallet.KeySet.PrivateKey);

    let account = new AccountWallet()
    account.Key = keyWallet;
    account.Child = [];
    account.IsImport = true;
    account.Name = accountName;

    this.MasterAccount.Child.push(account)

    this.Save(this.PassPhrase)

    return account
  }

  Save(password) {
    if (password == "") {
      password = this.PassPhrase
    }

    // parse to byte[]
    let data = JSON.stringify(this)

    // encrypt
    let cipherText = CryptoJS.AES.encrypt(data, password)

    // storage
    if (this.Storage != null) {
      this.Storage.setItem("Wallet", cipherText);
    }
  }

  LoadWallet(password) {
    if (this.Storage != null) {
      let cipherText = this.Storage.getItem("Wallet");
      let data = CryptoJS.AES.decrypt(cipherText, password)
      let jsonStr = data.toString(CryptoJS.enc.Utf8);

      try {
        let obj = JSON.parse(jsonStr);
        Object.setPrototypeOf(obj, Wallet.prototype);
        Object.setPrototypeOf(obj.MasterAccount, AccountWallet.prototype);
        Object.setPrototypeOf(obj.MasterAccount.Key, KeyWallet.prototype);
        for (let i = 0; i < obj.MasterAccount.Child.length; i++) {
          Object.setPrototypeOf(obj.MasterAccount.Child[i], AccountWallet.prototype);
          Object.setPrototypeOf(obj.MasterAccount.Child[i].Key, KeyWallet.prototype);
          Object.setPrototypeOf(obj.MasterAccount.Child[i].Key.ChainCode, Uint8Array.prototype);
          Object.setPrototypeOf(obj.MasterAccount.Child[i].Key.ChildNumber, Uint8Array.prototype);
          Object.setPrototypeOf(obj.MasterAccount.Child[i].Key.KeySet, keyset.KeySet.prototype);
        }
        delete obj.Storage
        Object.assign(this, obj)
      } catch (e) {
        throw e;
      }
    }
  }
}

class DefaultStorage {
  constructor() {
    this.Data = {}
  }

  setItem(key, value) {
    this.Data[key] = value
  }

  getItem(key) {
    return this.Data[key];
  }
}

function Test() {
  let wallet = new Wallet()
  let storage = new DefaultStorage();
  wallet.Init("12345678", 0, "Wallet", storage);
  wallet.Save("12345678")

  let wallet2 = new Wallet()
  wallet2.Storage = storage
  wallet2.LoadWallet("12345678")

  wallet2.CreateNewAccount("Test 2")

  console.log("End test")
}

Test();

module.exports = {Wallet, AccountWallet,}