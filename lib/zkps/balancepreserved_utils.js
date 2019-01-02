var common = require("../common");
var utils = require('../privacy_utils')
var Curve = new common.Elliptic('p256');
var InnerProdArg = { L,R,A,B,Challenges};
var CryptoParams = {
    C,BPG,BPH,N,U,V,G,H,
    Zero: function () {

    }
};
function InnerProductProveSub(proof, G, H, a, b, u, P){
    if  (a.length === 1) {
        proof.A = a[0]
        proof.B = b[0]
        return proof
    }
    curIt = Math.log2(a.length).toFixed(0)-1
    nprime = a.length/2
    let cl = InnerProduct(a[0:nprime],b[nprime:])
    let cr = InnerProduct()
    let L  = TwoVectorPCommitWithGens().add(u.mul(cl))
    let R  = TwoVectorPCommitWithGens().add(u.mul(cr))
    proof.L[curIt] = L
    proof.R[curIt] = R


}
function GenerateNewParams(G,H,x,L,R,P){
    let nprime = G.length/2;
    let Gprime = [];
    let Hprime = [];
    let xinv = x.invm(Curve.curve.n);
    for (let i=0;i<nprime;i++){
        Gprime[i] = G[i].mul(xinv).add(G[i+nprime].mul(x));
        Hprime[i] = H[i].mul(x).add(H[i+nprime].mul(xinv));
    }
    let x2 = x.mul(x);
    x2 = x2.mod(Curve.curve.n);
    let xinv2 = x.invm(Curve.curve.n);
    let Pprime = L.mul(x2).add(P).add(R.mul(xinv2));
    return [Gprime , Hprime , Pprime]
}












function InnerProduct(a, b) {
    if (a.length !== b.length){
       // privacy.NewPrivacyErr(privacy.UnexpectedErr, errors.New("InnerProduct: Uh oh! Arrays not of the same length"))
    }

    let c = new common.BigInt("0",10);
    for (let i = 0;i< a.length;i++) {
        let tmp = a[i].mul(b[i]);
        c = c.add(tmp);
        c = c.mod(Curve.curve.n);
    }
    return c
}
function VectorAdd(v,w){
    if(v.length!==w.length){
        // error
    }
    let result = [];
    for (let i=0;i<v.length;i++){
        result[i] = v[i].add(w[i])
        result[i] = result[i].mod(Curve.curve.n)
    }
    return result
}
function VectorHadamard(v, w) {
    if (v.length !== w.length) {
        //privacy.NewPrivacyErr(privacy.UnexpectedErr, errors.New("VectorHadamard: Uh oh! Arrays not of the same length"))
    }

    let result = [];

    for (let i=0;i< v.length;i++){
        result[i] = v[i].mul(w[i]);
        result[i] = result[i].mod(Curve.curve.n);
    }
    return result
}
function VectorAddScalar(v, s){
    result = [];
    for (let i=0;i < v.length;i++) {
        result[i] = v[i].add(s);
        result[i] = result[i].mod(Curve.curve.n);
    }
    return result
}
function ScalarVectorMul(v,s) {
    result = [];
    for (let i=0;i< v.length;i++){
        result[i] = v[i].mul(s);
        result[i] = result[i].mod(Curve.curve.n);
    }
    return result
}
function PadLeft(str,pad,l){
    let strCopy = str;
    while (strCopy.length < l){
        strCopy = pad + strCopy
    }
    return strCopy
}


// function StrToBigIntArray(str){
//     result = [];
//     for (let i=0;i<str.length;i++){
//         t, success
//     }
// }

function reverse(arr) {
    let result = [];
    let leng = arr.length;
    for(let i=0;i< arr.length; i++){
        result[i] = arr[leng-i-1]
    }
    return result
}
function PowerVector(l,base) {
    let result = [];

    for(let i=0;i<l;i++){
        result[i] = base.pow(new common.BigInt(i));
        result[i] = result[i].mod(Curve.n);
    }
}
function RandVector(l){
    let result = [];
    for (let i=0;i<l;i++){
        x = utils.RandInt(32);
        x = x.mod(Curve.n);
        result[i] = x
    }
    return result
}
function VectorSum(y) {
    result = new common.BigInt("0",10)
    for (let j=0;j<y.length;j++){
        result = result.add(j)
        result = result.mod(Curve.n)
    }
    return result
}
function TwoVectorPCommitWithGens(G, H , a, b ) {
    if (G.length!== H.length || G.length!== a.length|| a.length !== b.length) {
        return null
    }
    let commitment = new Curve.curve.point("0","0")
    for (var i = 0; i < len(G); i++) {
        let modA = a[i].mod(Curve.n);
        let modB = b[i].mod(Curve.n);
        ommitment = commitment.add(G[i].mul(modA)).add(H[i].mul(modB));
    }
    return commitment
}