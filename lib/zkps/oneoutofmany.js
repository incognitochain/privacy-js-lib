let common = require('../common');
let ec = require('../ec');
let P256 = require('../ec').P256;
let constants = require('../constants');
let key = require('../key');
let utils = require('../privacy_utils');
let aes = require('../aes');
let elgamal = require('../elgamal');
let pc = require('../pedersen');


class OneOutOfManyStatement{
    constructor(){
        this.commitments = [];
    }

    set(commitments){
        this.commitments = commitments
    }
}


class OneOutOfManyWitness {
    constructor() {
        this.rand = new common.BigInt(0);
        this.indexIsZero = 0;
        this.stmt = new OneOutOfManyStatement();
    }

    set(commitments, rand, indexIsZero) {
        this.rand = rand;
        this.indexIsZero = indexIsZero;
        this.stmt.set(commitments);
    }
    prove(){
        // Check the number of Commitment list's elements
        let N = this.stmt.commitments.length;
        if (N !== constants.CMRingSize) {
            return {
                proof: new OneOutOfManyProof(),
                err: new Error("the number of Commitment list's elements must be equal to CMRingSize")
            }
        }

        let n = constants.CMRingSizeExp;

        // Check indexIsZero
        if (this.indexIsZero > N) {
            return {
                proof: new OneOutOfManyProof(),
                err: new Error("Index is zero must be Index in list of commitments")
            }
        }

        // represent indexIsZero in binary
        let indexIsZeroBinary = utils.ConvertIntToBinary(int(wit.indexIsZero), n)

        // randomness array
        let r = new Array(n);       // big int array
        let a = new Array(n);       // big int array
        let s = new Array(n);       // big int array
        let t = new Array(n);       // big int array
        let u = new Array(n);       // big int array

        let cl = new Array(n);       // elliptic point array
        let ca = new Array(n);       // elliptic point array
        let cb = new Array(n);       // elliptic point array
        let cd = new Array(n);       // elliptic point array

        for (let j = 0; j < n; j++) {
            // Generate random numbers
            r[j] = utils.RandInt();
            a[j] = utils.RandInt();
            s[j] = utils.RandInt();
            t[j] = utils.RandInt();
            u[j] = utils.RandInt();

            // convert indexIsZeroBinary[j] to big.Int
            let indexInt = new common.BigInt(indexIsZeroBinary[j]);

            // Calculate cl, ca, cb, cd
            // cl = Com(l, r)
            cl[j] = pc.PedCom.CommitAtIndex(indexInt, r[j], constants.SK);

            // ca = Com(a, s)
            ca[j] = pc.PedCom.CommitAtIndex(a[j], s[j], constants.SK);

            // cb = Com(la, t)
            // la := new(big.Int).Mul(indexInt, a[j])
            // la.Mod(la, privacy.Curve.Params().N)
            // cb[j] = privacy.PedCom.CommitAtIndex(la, t[j], privacy.SK)
        }




        return new OneOutOfManyProof();
    }

}

class OneOutOfManyProof {
    constructor() {
        this.cl = [];          // []EllipticPoint
        this.ca = [];          // []EllipticPoint
        this.cb = [];          // []EllipticPoint
        this.cd = [];          // []EllipticPoint
        this.f = [];           // [] BigInt
        this.za = [];          // [] BigInt
        this.zb = [];          // [] BigInt
        this.zd = new common.BigInt(0);
        this.commitments = [];
        this.commitmentIndices = [];
        this.index = 0;
    }

    isNull() {
        if (this.cl.length === 0) {
            return true;
        }
        if (this.ca.length === 0) {
            return true;
        }
        if (this.cb.length === 0) {
            return true;
        }
        if (this.cd.length === 0) {
            return true;
        }
        if (this.f.length === 0) {
            return true;
        }
        if (this.za.length === 0) {
            return true;
        }
        if (this.zb.length === 0) {
            return true;
        }
        if (this.zd.eq(0)) {
            return true;
        }
        if (this.commitments.length === 0) {
            return true;
        }
        if (this.commitmentIndices.length === 0) {
            return true;
        }
        return this.index === 0;
    }

    set(commitmentIndices, commitments, cl, ca, cb, cd, f, za, zb, zd, index) {
        this.commitmentIndices = commitmentIndices;
        this.commitments = commitments;
        this.cl = cl;
        this.ca = ca;
        this.cb = cb;
        this.cd = cd;
        this.f = f;
        this.za = za;
        this.zb = zb;
        this.zd = zd;
        this.index = index;
        return this;
    }
    toBytes(){
        // if proof is null, return an empty array
        if (this.isNull()) {
            return [];
        }

        // N = 2^n
        let N = constants.CMRingSize;
        let n = constants.CMRingSizeExp;

        let bytes = [];

        // convert array cl to bytes array
        for (let i = 0; i < n; i++) {
            bytes = bytes.concat(this.cl[i].compress());
        }
        // convert array ca to bytes array
        for (let i = 0; i < n; i++) {
            bytes = bytes.concat(this.ca[i].compress());
        }

        // convert array cb to bytes array
        for (let i = 0; i < n; i++) {
            bytes = bytes.concat(bytes, this.cb[i].compress());
        }

        // convert array cd to bytes array
        for (let i = 0; i < n; i++) {
            bytes = bytes.concat(this.cd[i].compress());
        }
        return bytes;
    }
}

module.exports = {OneOutOfManyWitness, OneOutOfManyProof }
