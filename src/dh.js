'use strict';

const base64 = require('./base64');
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
 * Arguments:
 *   pub: CryptoKey representing a DH public key
 *
 * Returns: Promise resolving to a string with the hex SHA-256 hash
 * of the SPKI representation of the public key.
 */
async function fingerprint(pub) {
  const spki = await cs.exportKey("spki", pub);
  const digest = await cs.digest("SHA-256", spki);
  return base64.stringify(digest);
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
  fingerprint: fingerprint,
  test: test,
}
