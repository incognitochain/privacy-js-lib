var common = require("./common");
var utils = require('./privacy_utils')
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
            console.log(this.Coeffs[i].toString(10,""));
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

//Usage
//
// let V = [];
// let U = [];
// for (let i=0;i<5;i++){
//     V[i] = utils.RandInt(32);
//     U[i] = utils.RandInt(32)
//     // console.log(V[i].toString(10, ""))
// }
// V[5] = new common.BigInt("1")
// V[6] = new common.BigInt("50")
// V[7] = new common.BigInt("0")
// V[8] = new common.BigInt("0")
// p = new Poly(V)
//
// q = new Poly(U)
//
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
