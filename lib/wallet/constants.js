const PriKeyType         = 0x0; // Serialize wallet account key into string with only PRIVATE KEY of account keyset
const PaymentAddressType = 0x1; // Serialize wallet account key into string with only PAYMENT ADDRESS of account keyset
const ReadonlyKeyType    = 0x2; // Serialize wallet account key into string with only READONLY KEY of account keyset

const PriKeySerializeSize  = 71;
const PaymentAddrSerializeSize  = 69;
const ReadonlyKeySerializeSize  = 68;



module.exports = {PriKeyType, PaymentAddressType, ReadonlyKeyType, PriKeySerializeSize, PaymentAddrSerializeSize, ReadonlyKeySerializeSize};