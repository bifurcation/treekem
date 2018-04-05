'use strict';

const cs = window.crypto.subtle;
  
const ECDH_KEY_USAGES = ["deriveKey"];
const AES_GCM_KEY_USAGES = ["encrypt", "decrypt"];

const ECDH_GEN = { name: "ECDH", namedCurve: "P-256" };
const AES_GCM_GEN = { name: "AES-GCM", length: 128 };

function ECDH_DERIVE(pub) {
  return { 
    name: "ECDH", 
    namedCurve: "P-256", 
    public: pub,
  };
}

function AES_GCM_ENC(iv) {
  return { 
    name: "AES-GCM", 
    iv: iv || crypto.getRandomValues(new Uint8Array(12)),
  };
}

/*
 * Arguments:
 *   plaintext: The value to be encrypted, as a BufferSource
 *   pub:       Public key for the receiver
 *
 * Returns: Promise resolving to an ECKEMCiphertext object:
 *   {
 *     pub: CryptoKey
 *     iv: BufferSource
 *     ct: BufferSource
 *   }
 */
function encrypt(plaintext, pubA) {
  let pubE;
  let iv;
  return cs.generateKey(ECDH_GEN, false, ECDH_KEY_USAGES)
    .then(kp => {
      pubE = kp.publicKey;
      let alg = ECDH_DERIVE(pubA);
      alg.public = pubA;
      return cs.deriveKey(alg, kp.privateKey, AES_GCM_GEN, false, AES_GCM_KEY_USAGES);
    })
    .then(k => {
      let alg = AES_GCM_ENC();
      iv = alg.iv;
      return cs.encrypt(alg, k, plaintext);
    })
    .then(ct => {
      return {pub: pubE, iv: iv, ct: ct};
    })
}

/*
 * Arguments:
 *   ciphertext: The value to be decrypted, as an object
 *   priv:       Private key for the receiver
 *
 * Returns: Promise<ArrayBuffer>
 */
function decrypt(ciphertext, priv) {
  let alg = ECDH_DERIVE(ciphertext.pub);
  return cs.deriveKey(alg, priv, AES_GCM_GEN, false, AES_GCM_KEY_USAGES)
    .then(k => {
      let alg = AES_GCM_ENC(ciphertext.iv);
      return cs.decrypt(alg, k, ciphertext.ct);
    });
}

/*
 * Self-test: Encrypt/decrypt round trip
 */
function test() {
  let keyPair;
  const original = new Uint8Array([0,1,2,3]);

  cs.generateKey(ECDH_GEN, false, ECDH_KEY_USAGES)
    .then(kp => {
      keyPair = kp;
      return encrypt(original, keyPair.publicKey);
    })
    .then(encrypted => {
      return decrypt(encrypted, keyPair.privateKey);
    })
    .then(decrypted => {
      let equal = (Array.from(decrypted).filter((x,i) => (original[i] != x)).length == 0)
      console.log("[ECKEM]", equal? "PASS" : "FAIL");
    })
    .catch(err => {
      console.log("[ECKEM] FAIL:", err);
    });
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
  test: test,
}
