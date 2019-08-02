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
//     V[i] = utils.RandScalar(8);
//     // U[i] = utils.RandInt(8)
//     // console.log(V[i].toString(10, ""))
// }
// for (let i=0;i<6;i++){
//     // V[i] = utils.RandInt(8);
//     U[i] = utils.RandScalar(8)
//     // console.log(V[i].toString(10, ""))
// }
// p = new Poly(V)
// q = new Poly(U)
// p.print();
// console.log('--------------');
// q.print();
// console.log('--------------');
// let r = p.mul(q,null);
// p.print();
// console.log('--------------');
// q.print();
// console.log('--------------');
// let r = p.sub(q,null)
// console.log("P-Q--------")
// r.print()
// console.log("Q+P--------")
// let k = q.add(p,null)
// k.print()
// console.log("2P---------")
// p.add(p,null).print()
// console.log("P-Q + P+Q---------")
// k.add(r,null).print()