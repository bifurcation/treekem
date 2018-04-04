'use strict';

const cs = window.crypto.subtle;
const EC = require('elliptic').ec;
const BN = require('bn.js');

const p256 = new EC('p256');

const ENDIAN = 'be';
const INTLEN = 32;

function bn2b64(n) {
  const bytes = n.toArray(ENDIAN, INTLEN);
  let base64 = (new Buffer(bytes)).toString('base64');
  return base64.replace(/=/g, '')
               .replace(/\+/g, '-')
               .replace(/\//g, '_');
}

function bin2jwk(val) { 
  const arr = Array.from(new Uint8Array(val));
  const hex = arr.map(x => ('0' + x.toString(16)).slice(-2)).join("");
  const priv = new BN(hex, 16);
  const keyPair = p256.keyFromPrivate(priv);
  
  // This computes the public key from the private key
  keyPair.getPublic();
  
  const d = bn2b64(priv);
  const x = bn2b64(keyPair.pub.x.fromRed());
  const y = bn2b64(keyPair.pub.y.fromRed());
  return {
    priv: {kty: "EC", crv: "P-256", x: x, y: y, d: d},
    pub: {kty: "EC", crv: "P-256", x: x, y: y},
  };
}

function jwk2wc(pair) {
  let priv;
  const alg = {
    name: "ECDH",
    namedCurve: "P-256",
  }

  return cs.importKey("jwk", pair.priv, alg, false, ["deriveKey", "deriveBits"])
    .then(k => {
      priv = k;
      console.log("[jwk2kp] got private key", priv);
      return cs.importKey("jwk", pair.pub, alg, true, []);
    })
    .then(pub => {
      console.log("[jwk2kp] got public key", pub);
      return {privateKey: priv, publicKey: pub};
    });
}

// Injection from byte strings to key pairs
function iota(secret) {
  return cs.digest("SHA-256", secret)
    .then(bin2jwk)
    .then(jwk2wc);
}

module.exports = iota;
