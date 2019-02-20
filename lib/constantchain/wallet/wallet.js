const PriKeyType = require('constants');
const KeyWallet = require("./hdwallet").KeyWallet;
const NewMasterKey = require("./hdwallet").NewMasterKey;
const MnemonicGenerator = require("./mnemonic").MnemonicGenerator;
var CryptoJS = require("crypto-js");

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
    this.Entropy = mnemonicGen.NewEntropy(128);
    this.Mnemonic = mnemonicGen.NewMnemonic(this.Entropy);
    this.Seed = mnemonicGen.NewSeed(this.Mnemonic, passPhrase);

    let masterKey = NewMasterKey(this.Seed);

    this.MasterAccount = new AccountWallet()
    this.MasterAccount.Key = masterKey;
    this.MasterAccount.Child = [];
    this.MasterAccount.Name = "master";

    if (numOfAccount == 0) {
      numOfAccount = 1;
    }

    for (let i = 0; i < numOfAccount; i++) {
      let childKey = this.MasterAccount.NewChildKey(i);
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
    this.Save(passPhrase)

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
      }
    }
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

    this.Save(passPhrase)

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
      JSON.parse(data, this);
    }
  }
}

function Test() {
  let wallet = new Wallet()
  wallet.Init("12345678", 0, "Wallet");
  console.log(wallet)
}

Test();

module.exports = {Wallet, AccountWallet,}