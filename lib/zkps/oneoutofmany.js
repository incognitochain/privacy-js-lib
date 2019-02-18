let BigInt = require('bn.js');
const P256 = require('../ec').P256;
let constants = require('../constants');
const utils = require('../privacy_utils');
const zkpUtils = require('./utils');
const pc = require('../pedersen');
let poly = require('../polynomials');


class OneOutOfManyStatement {
    constructor() {
        this.commitments = [];
    }

    set(commitments) {
        this.commitments = commitments
    }
}


class OneOutOfManyWitness {
    constructor() {
        this.rand = new BigInt(0);
        this.indexIsZero = 0;
        this.stmt = new OneOutOfManyStatement();
    }

    set(commitments, rand, indexIsZero) {
        this.rand = rand;
        this.indexIsZero = indexIsZero;
        this.stmt.set(commitments);
    }

    prove() {
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
        let indexIsZeroBinary = utils.ConvertIntToBinary(this.indexIsZero, n);

        // randomness array
        let r = new Array(n); // big int array
        let a = new Array(n); // big int array
        let s = new Array(n); // big int array
        let t = new Array(n); // big int array
        let u = new Array(n); // big int array

        let cl = new Array(n); // elliptic point array
        let ca = new Array(n); // elliptic point array
        let cb = new Array(n); // elliptic point array
        let cd = new Array(n); // elliptic point array

        for (let j = 0; j < n; j++) {
            // Generate random numbers
            r[j] = utils.RandScalar();
            a[j] = utils.RandScalar();
            s[j] = utils.RandScalar();
            t[j] = utils.RandScalar();
            u[j] = utils.RandScalar();

            // convert indexIsZeroBinary[j] to big.Int
            let indexInt = new BigInt(indexIsZeroBinary[j]);

            // Calculate cl, ca, cb, cd
            // cl = Com(l, r)
            cl[j] = pc.PedCom.CommitAtIndex(indexInt, r[j], constants.SK);

            // ca = Com(a, s)
            ca[j] = pc.PedCom.CommitAtIndex(a[j], s[j], constants.SK);

            // cb = Com(la, t)
            let la = indexInt.mul(a[j]);
            cb[j] = pc.PedCom.CommitAtIndex(la, t[j], constants.SK);

            console.log('a: ', j, ': ', a[j].toArray().join(', '));
            console.log('u: ', j, ': ', u[j].toArray().join(', '));
        }

        console.log();

        // Calculate: cd_k = ci^pi,k
        for (let k = 0; k < n; k++) {
            // Calculate pi,k which is coefficient of x^k in polynomial pi(x)
            cd[k] = pc.PedCom.CommitAtIndex(new BigInt(0), u[k], constants.SK);

            for (let i = 0; i < N; i++) {
                console.log('k: ', k);
                console.log('i: ', i);
                let iBinary = utils.ConvertIntToBinary(i, n);
                console.log('iBinary: ', iBinary);
                console.log('n: ', n);
                console.log('a0: ', a[0].toArray().join(', '));
                console.log('a1: ', a[1].toArray().join(', '));
                console.log('a2: ', a[2].toArray().join(', '));
                console.log('indexIsZeroBinary: ', indexIsZeroBinary);

                let pik = GetCoefficient(iBinary, k, n, a, indexIsZeroBinary);

                console.log('pik: ', pik.toArray().join(', '));
                cd[k] = cd[k].add(this.stmt.commitments[i].mul(pik));
                // console.log('cd ', i, ': ', cd[k].compress().join(', '));
                console.log();
            }

            console.log('cd ', k, ': ', cd[k].compress().join(', '));
        }

        // Calculate challenge x
        let x = new BigInt(0);

        for (let j = 0; j < n; j++) {
            x = zkpUtils.generateChallenge([x.toArray('be', constants.BigIntSize), cl[j].compress(), ca[j].compress(), cb[j].compress(), cd[j].compress()]);
        }

        console.log("Challenge x: ", x.toArray('be', constants.BigIntSize));

        // Calculate za, zb zd
        let za = new Array(n); // big int array
        let zb = new Array(n); // big int array
        let f = new Array(n); // big int array

        for (let j = 0; j < n; j++) {
            // f = lx + a
            let indexInt = new BigInt(indexIsZeroBinary[j]);
            f[j] = indexInt.mul(x);
            f[j] = f[j].add(a[j]);
            f[j] = f[j].umod(P256.n);

            // za = s + rx
            za[j] = r[j].mul(x);
            za[j] = za[j].add(s[j]);
            za[j] = za[j].umod(P256.n);

            // zb = r(x - f) + t
            zb[j] = x.sub(f[j]);
            zb[j] = zb[j].mul(r[j]);
            zb[j] = zb[j].add(t[j]);
            zb[j] = zb[j].umod(P256.n);
        }

        // zd = rand * x^n - sum_{k=0}^{n-1} u[k] * x^k
        let zd = x.pow(new BigInt(n));
        zd = zd.mul(this.rand);

        // let uxInt = new BigInt(0);
        let sumInt = new BigInt(0);
        for (let k = 0; k < n; k++) {
            let uxInt = x.pow(new BigInt(k));
            uxInt = uxInt.mul(u[k]);
            sumInt = sumInt.add(uxInt);
            // sumInt = sumInt.umod(P256.n);
        }

        zd = zd.sub(sumInt);
        zd = zd.umod(P256.n);

        let proof = new OneOutOfManyProof();
        proof.set(this.stmt.commitments, cl, ca, cb, cd, f, za, zb, zd);


        //Test

        // let left1 = pc.PedCom.G[constants.RAND].mul(r[0].mul(x).add(s[0]));
        // let right1 = pc.PedCom.CommitAtIndex(new BigInt(0), za[0], constants.SK);
        //
        // if (left1.eq(right1)){
        //     console.log("Rightttttttttttttttt");
        // } else{
        //     console.log("Wrongggggggggggggggg");
        // }

        // for (let i=0; i<n; i++){
        //     let left1 = cl[i].mul(x).add(ca[i]);
        //     let right1 = pc.PedCom.CommitAtIndex(f[i], za[i], constants.SK);
        //
        //     if (left1.eq(right1)){
        //         console.log("Rightttttttttttttttt");
        //     } else{
        //         console.log("Wrongggggggggggggggg");
        //     }
        // }

        let leftPoint = P256.curve.point();

        for (let i = 0; i < N; i++) {
            let iBinary = utils.ConvertIntToBinary(i, n);
            let exp = new BigInt(1);
            let fji = new BigInt(1);

            for (let j = 0; j < n; j++) {
                if (iBinary[j] === 1) {
                    fji = f[j]
                } else {
                    fji = x.sub(f[j]);
                    fji = fji.umod(P256.n);
                }

                exp = exp.mul(fji);
                exp = exp.umod(P256.n);
            }

            if (i === 0) {
                leftPoint = this.stmt.commitments[i].mul(exp)
            } else {
                leftPoint = leftPoint.add(this.stmt.commitments[i].mul(exp))
            }
        }

        let leftPoint2 = P256.curve.point();

        for (let k = 0; k < n; k++) {
            let xk = x.pow(new BigInt(k));
            xk = xk.umod(P256.n);

            if (k === 0) {
                leftPoint2 = cd[k].mul(xk);
            } else {
                leftPoint2 = leftPoint2.add(cd[k].mul(xk));
            }
        }

        leftPoint = leftPoint.add(leftPoint2);

        let rightPoint = pc.PedCom.CommitAtIndex(new BigInt(0), zd, constants.SK);

        if (leftPoint.eq(rightPoint)) {
            console.log('Righttttttttt')
        } else {
            console.log('Wrongggggggggg');

            let tmpPoint = leftPoint.add(rightPoint.inverse());
            console.log('tmpPoint: ', tmpPoint);
        }

        return {
            proof: proof,
            err: null
        }
    }
}

class OneOutOfManyProof {
    constructor() {
        this.cl = []; // []EllipticPoint
        this.ca = []; // []EllipticPoint
        this.cb = []; // []EllipticPoint
        this.cd = []; // []EllipticPoint
        this.f = []; // [] BigInt
        this.za = []; // [] BigInt
        this.zb = []; // [] BigInt
        this.zd = new BigInt(0);
        this.stmt = new OneOutOfManyStatement();
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
        return this.stmt.commitments.length === 0
    }

    set(commitments, cl, ca, cb, cd, f, za, zb, zd) {
        this.stmt.commitments = commitments;
        this.cl = cl;
        this.ca = ca;
        this.cb = cb;
        this.cd = cd;
        this.f = f;
        this.za = za;
        this.zb = zb;
        this.zd = zd;
        return this;
    }

    toBytes() {
        // if proof is null, return an empty array
        if (this.isNull()) {
            return [];
        }

        let bytes = new Uint8Array(constants.OneOfManyProofSize);
        let offset = 0;

        // N = 2^n
        let N = constants.CMRingSize;
        let n = constants.CMRingSizeExp;

        // convert array cl to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.cl[i].compress(), offset);
            offset += constants.CompressPointSize;
        }
        // convert array ca to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.ca[i].compress(), offset);
            offset += constants.CompressPointSize;
        }

        // convert array cb to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.cb[i].compress(), offset);
            offset += constants.CompressPointSize;
        }

        // convert array cd to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.cd[i].compress(), offset);
            offset += constants.CompressPointSize;
        }

        // convert array f to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.f[i].toArray('be', constants.BigIntSize), offset);
            offset += constants.BigIntSize;
        }

        // convert array za to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.za[i].toArray('be', constants.BigIntSize), offset);
            offset += constants.BigIntSize;
        }

        // convert array zb to bytes array
        for (let i = 0; i < n; i++) {
            bytes.set(this.zb[i].toArray('be', constants.BigIntSize), offset);
            offset += constants.BigIntSize;
        }

        bytes.set(this.zd.toArray('be', constants.BigIntSize), offset);
        return bytes;
    }
}

// Get coefficient of x^k in the polynomial p_i(x)
function GetCoefficient(iBinary, k, n, a, l) {
    let res = new poly.Poly([new BigInt(1)]);
    let fji = new poly.Poly([]);

    for (let j = n - 1; j >= 0; j--) {
        let fj = new poly.Poly([a[j], new BigInt(l[j])]);
        if (iBinary[j] == 0) {
            fji = new poly.Poly([new BigInt(0), new BigInt(1)]).Sub(fj, P256.n);
        } else {
            fji = fj;
        }
        // console.log('fji: ');
        // fji.print();
        res = res.Mul(fji, P256.n);
    }

    if (res.GetDegree() < k) {
        return new BigInt(0);
    }

    // console.log("RES when get coeeficient: ", res);
    return res.Coeffs[k];
}

function TestGetCoefficient() {

    let a = new Array(3);

    a[0] = new BigInt([28, 30, 162, 177, 161, 127, 119, 10, 195, 106, 31, 125, 252, 56, 111, 229, 236, 245, 202, 172, 27, 54, 110, 9, 9, 8, 56, 189, 248, 100, 190, 129]);
    a[1] = new BigInt([144, 245, 78, 232, 93, 155, 71, 49, 175, 154, 78, 81, 146, 120, 171, 74, 88, 99, 196, 61, 124, 156, 35, 55, 39, 22, 189, 111, 108, 236, 3, 131]);
    a[2] = new BigInt([224, 15, 114, 83, 56, 148, 202, 7, 187, 99, 242, 4, 2, 168, 169, 168, 44, 174, 215, 111, 119, 162, 172, 44, 225, 97, 236, 240, 242, 233, 148, 49]);

    let res = GetCoefficient([0, 1, 1], 3, 3, a, [0, 1, 1]);

    // let expectedRes = new BigInt(-6);
    // expectedRes = expectedRes.umod(P256.n);
    // console.log('expected res: ', expectedRes);
    console.log('res: ', res.toArray().join(' '));
}

// TestGetCoefficient();

function TestOneOutOfMany() {
    let N = constants.CMRingSize;
    let n = constants.CMRingSizeExp;

    // for (let i = 0; i < N; i++) {
    //     commitments[i] = P256.randomize();
    //     console.log("commitment: ", i, commitments[i].compress().join(', '));
    // }

    let commitments = new Array(N);
    commitments[0] = P256.decompress([2, 63, 242, 198, 114, 250, 36, 102, 85, 80, 173, 148, 153, 247, 78, 215, 30, 54, 40, 193, 40, 190, 206, 73, 198, 39, 23, 48, 56, 136, 58, 91, 167]);

    commitments[1] = P256.decompress([2, 203, 30, 129, 126, 123, 135, 125, 29, 43, 137, 52, 148, 146, 17, 87, 85, 237, 67, 191, 175, 241, 86, 102, 239, 183, 114, 78, 11, 127, 116, 16, 143]);

    commitments[2] = P256.decompress([2, 123, 251, 169, 31, 79, 237, 122, 212, 173, 208, 175, 20, 111, 140, 19, 185, 72, 17, 229, 163, 84, 255, 63, 157, 51, 251, 209, 160, 122, 250, 30, 116]);

    commitments[3] = P256.decompress([2, 174, 247, 205, 128, 120, 191, 95, 219, 186, 227, 95, 10, 157, 200, 224, 109, 152, 179, 5, 188, 162, 125, 167, 214, 127, 178, 173, 246, 109, 18, 23, 254]);

    commitments[4] = P256.decompress([2, 8, 49, 76, 243, 238, 108, 171, 35, 55, 118, 239, 95, 214, 43, 88, 155, 4, 152, 62, 74, 15, 62, 203, 158, 189, 163, 62, 150, 255, 220, 14, 170]);

    commitments[5] = P256.decompress([3, 205, 17, 244, 179, 44, 154, 114, 20, 78, 113, 196, 20, 133, 98, 165, 111, 74, 139, 53, 74, 224, 153, 41, 66, 224, 190, 220, 179, 136, 193, 241, 218]);

    commitments[6] = P256.decompress([3, 191, 145, 66, 202, 76, 92, 64, 185, 89, 85, 149, 239, 190, 231, 208, 214, 25, 0, 218, 142, 114, 18, 188, 122, 111, 213, 6, 108, 128, 129, 122, 109]);

    commitments[7] = P256.decompress([2, 186, 15, 36, 170, 79, 9, 118, 9, 249, 10, 215, 114, 5, 80, 9, 156, 206, 217, 242, 156, 30, 210, 169, 109, 221, 103, 37, 186, 24, 88, 47, 121]);

    console.log();

    let indexIsZero = 3;
    let randIsZero = new BigInt(100);
    commitments[indexIsZero] = pc.PedCom.CommitAtIndex(0, randIsZero, constants.SK);

    let wit = new OneOutOfManyWitness();
    wit.set(commitments, randIsZero, indexIsZero);
    let proof = wit.prove();
    for (let i = 0; i < n; i++) {
        console.log("cl ", i, ": ", proof.proof.cl[i].compress().join(', '));
        console.log("ca ", i, ": ", proof.proof.ca[i].compress().join(', '));
        console.log("cb ", i, ": ", proof.proof.cb[i].compress().join(', '));
        console.log("cd ", i, ": ", proof.proof.cd[i].compress().join(', '));
        console.log("f ", i, ": ", proof.proof.f[i].toArray().join(', '));
        console.log("za ", i, ": ", proof.proof.za[i].toArray().join(', '));
        console.log("zb ", i, ": ", proof.proof.zb[i].toArray().join(', '));

        console.log("commitments ", i, ": ", proof.proof.stmt.commitments[i].compress().join(', '));
        console.log();
        console.log();
    }
    console.log("zd : ", proof.proof.zd.toArray().join(', '));

    // console.log("Proof struct: ", proof.proof);
    console.log("Proof byte: ", proof.proof.toBytes().join(', '));
    console.log("Proof byte len: ", proof.proof.toBytes().length);
}

// TestOneOutOfMany();


module.exports = {
    OneOutOfManyWitness,
    OneOutOfManyProof
};