const { P256 } = require('./ec');

// Polynomial
class Poly {
    constructor(coeffs) {
        // f(x) = 3x^3 + 2x + 1 => [1 2 0 3]
        this.Coeffs = [];
        for (let i = 0; i < coeffs.length; i++) {
            this.Coeffs[i] = coeffs[i];
        }
    }

    trim() {
        let deg = this.getDegree();
        for (let i = deg; i > 0; i--) {
            if (!this.Coeffs[i].isZero()) {
                break;
            } else {
                this.Coeffs.pop();
            }
        }
    }

    print() {
        for (let i = 0; i < this.Coeffs.length; i++) {
            console.log(this.Coeffs[i].umod(P256.n).toString(10, ""));
        }
    }

    neg() {
        var p = new Poly(this.Coeffs);
        for (let i = 0; i < this.Coeffs.length; i++) {
            p.Coeffs[i] = this.Coeffs[i].neg();
        }
        return p;
    }

    sub(q, n) {
        let r = q.neg();
        return this.add(r, n);
    }

    add(q, n) {
        if (this.compare(q) < 0) {
            return q.add(this, n)
        }
        let r = [];
        for (let i = 0; i < q.Coeffs.length; i++) {
            r[i] = this.Coeffs[i];
            r[i] = r[i].add(q.Coeffs[i]);
        }
        for (let i = q.Coeffs.length; i < this.Coeffs.length; i++) {
            r[i] = this.Coeffs[i];
        }
        if (n != null) {
            for (let i = 0; i < this.Coeffs.length; i++) {
                r[i] = r[i].mod(n);
            }
        }
        let res = new Poly(r);
        res.trim();
        return res;
    }

    mul(q, n) {
        let P_deg = this.getDegree();
        let Q_deg = q.getDegree();
        let deg = P_deg + Q_deg + 1;
        let res = [];
        for (let i = 0; i <= P_deg; i++) {
            for (let j = 0; j <= Q_deg; j++) {
                res[i + j] = (res[i + j]) ? res[i + j].add(this.Coeffs[i].mul(q.Coeffs[j])) : this.Coeffs[i].mul(q.Coeffs[j]);
            }
        }
        if (n != null) {
            for (let i = 0; i < deg; i++) {
                res[i] = res[i].umod(n)
            }
        }
        let P = new Poly(res);
        P.trim();
        return P;
    }

    compare(q) {
        if (this.getDegree() < q.getDegree()) {
            return -1
        }
        if (this.getDegree() > q.getDegree()) {
            return 1
        }
        for (let i = 0; i <= this.getDegree(); i++) {
            switch (this.Coeffs[i].cmp(q.Coeffs[i])) {
                case -1:
                    return -1;
                case 1:
                    return 1;
            }
        }
        return 0;
    }

    getDegree() {
        return this.Coeffs.length - 1;
    }
}

module.exports = {
    Poly
};