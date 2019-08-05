// move modInverse and power function to another file or overwrite operators for BigInt
// Modulo inverse using extended Euclid Algorithm
function modInverse(a, m) {
  let m0 = m;
  let y = BigInt("0")
  let x = BigInt("1");

  if (m == 1)
    return 0;

  while (a > 1) {
    // q is quotient
    let q = a / m;
    let t = m;

    // m is remainder now, process same as
    // Euclid's algo
    m = a % m;
    a = t;
    t = y;

    // Update y and x
    y = x - q * y;
    x = t;
  }

  // Make x positive
  if (x < 0)
    x = x + m0;

  return x;
}

// Fast Power using Exponential Squaring
function power(base, power, n) {
  let result = BigInt(1);
  const twoBN = BigInt(2);

  while (power > 0) {
    // if power id odd
    if (power % twoBN == 1) {
      result = (result * base) % n;
    }

    power = power / twoBN;
    base = (base * base) % n;
  }

  return result;
}

function umod(x, n) {
  return x % n + n
}

module.exports = {
  modInverse, power, umod
};
