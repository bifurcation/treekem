'use strict';

const cs = window.crypto.subtle;

const ECDH_KEY_USAGES = ["deriveBits"];
const ECDH_GEN = { name: "ECDH", namedCurve: "P-256" };
const SECRET_BITS = 256;

/*
 * Arguments: None
 *
 * Returns: Promise resolving to:
 *   {
 *     privateKey: CryptoKey,
 *     publicKey: CryptoKey,
 *   }
 */
async function newKeyPair() {
  return cs.generateKey(ECDH_GEN, false, ECDH_KEY_USAGES);
}

/*
 * Arguments:
 *   priv: CryptoKey representing a DH private key
 *   pub: CryptoKey representing a DH public key
 *
 * Returns: Promise resolving to ArrayBuffer
 */
async function secret(priv, pub) {
  const alg = { 
    name: "ECDH", 
    namedCurve: "P-256", 
    public: pub,
  };
  return cs.deriveBits(alg, priv, SECRET_BITS);
}

/*
 * Self-test: DH exchange
 */
async function test() {
  try {
    const kpA = await newKeyPair();
    const kpB = await newKeyPair();

    const ssAB = await secret(kpA.privateKey, kpB.publicKey);
    const ssBA = await secret(kpB.privateKey, kpA.publicKey);
    
    const equal = (Array.from(ssAB).filter((x,i) => (ssBA[i] != x)).length == 0);
    console.log("[DH]", equal? "PASS" : "FAIL");
  } catch (err) {
    console.log("[DH] FAIL:", err);
  }
}

module.exports = {
  newKeyPair: newKeyPair,
  secret: secret,
  test: test,
}
