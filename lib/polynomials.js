var common = require("./common");
var utils = require('./privacy_utils');
var P256 = require('./ec').P256;
class Poly{
    // Data structure for a polynomial
    // Just an array in reverse
    // f(x) = 3x^3 + 2x + 1 => [1 2 0 3]
    constructor(coeffs){
        this.Coeffs = [];
        for (let i=0;i<coeffs.length;i++){
            this.Coeffs[i] = coeffs[i];
        }
    }
    trim()
    {
        let last =0;
        let deg = this.GetDegree();
        for (let i=deg;i>0;i--){
            if (this.Coeffs[i].cmp(new common.BigInt("0"))!==0){
                break;
            }
            else {
                this.Coeffs.pop();
            }
        }
    }
    print(){
        for(let i=0;i<this.Coeffs.length;i++){
            console.log(this.Coeffs[i].umod(P256.n).toString(10,""));
        }
    }
    //return negative Poly
    Neg(){
        var p = new Poly(this.Coeffs);
        for (let i=0;i<this.Coeffs.length;i++){
            p.Coeffs[i] = this.Coeffs[i].neg();
        }
        return p;
    }
    Sub(q, n){
        let r = q.Neg();
        return this.Add(r,n);
    }
    Add(q,n){
        if (this.Compare(q) <0) {
            return q.Add(this,n)
        }
        let r = [];
        for (let i=0;i<q.Coeffs.length;i++){
            r[i] = this.Coeffs[i];
            r[i] = r[i].add(q.Coeffs[i]);
        }
        for (let i=q.Coeffs.length;i<this.Coeffs.length;i++){
            r[i] = this.Coeffs[i];
        }
        if (n!=null){
            for (let i=0;i<this.Coeffs.length;i++){
                r[i] = r[i].mod(n);
            }
        }
        let res = new Poly(r);
        res.trim();
        return res;
    }
    //todo: thunderbird
    Mul(q, n){
        let deg = this.GetDegree() + q.GetDegree()+1;
        let P_deg = this.GetDegree();
        let Q_deg = q.GetDegree();
        let res = [];
        for (let i=0;i<deg;i++){
            res[i] = new common.BigInt("0")
        }
        for (let i=0;i<=P_deg;i++) {
            for (let j = 0; j <=Q_deg; j++) {
                res[i + j] = res[i + j].add(this.Coeffs[i].mul(q.Coeffs[j]));
            }
        }
        if (n!=null){
            for (let i=0;i<deg;i++){
                res[i] = res[i].umod(n)
            }
        }
        let P = new Poly(res);
        P.trim();
        return P ;
    }
    Compare(q){
        if (this.GetDegree() <  q.GetDegree()){
            return -1
        }
        if (this.GetDegree() > q.GetDegree()){
            return 1
        }
        for (let i=0;i<=this.GetDegree();i++){
            switch (this.Coeffs[i].cmp(q.Coeffs[i])){
                case -1:
                    return -1;
                case 1:
                    return 1;
            }
        }
    }
    GetDegree(){
        return this.Coeffs.length-1;
    }
}


// function TestPoly(){
//     let a = new Poly([new common.BigInt(10)]);
//     let b = new Poly([new common.BigInt(10)], [new common.BigInt(20)]);
//     a = a.mul(b);
//     a.print();
// }
//
// TestPoly();

//Usage
//
// let V = [];
// let U = [];
// for (let i=0;i<3;i++){
//     V[i] = utils.RandInt(8);
//     // U[i] = utils.RandInt(8)
//     // console.log(V[i].toString(10, ""))
// }
// for (let i=0;i<6;i++){
//     // V[i] = utils.RandInt(8);
//     U[i] = utils.RandInt(8)
//     // console.log(V[i].toString(10, ""))
// }
// p = new Poly(V)
// q = new Poly(U)
// p.print();
// console.log('--------------');
// q.print();
// console.log('--------------');
// r = p.Mul(q,null);
// r.print();

// let r = p.Sub(q,null)
// console.log("P-Q--------")
// r.print()
// console.log("Q+P--------")
// let k = q.Add(p,null)
// k.print()
// console.log("2P---------")
// p.Add(p,null).print()
// console.log("P-Q + P+Q---------")
// k.Add(r,null).print()
module.exports ={
    Poly
};
