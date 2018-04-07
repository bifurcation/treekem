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
async function encrypt(plaintext, pubA) {
  const kpE = await cs.generateKey(ECDH_GEN, false, ECDH_KEY_USAGES);

  const dhAlg = ECDH_DERIVE(pubA);
  const ek = await cs.deriveKey(dhAlg, kpE.privateKey, AES_GCM_GEN, false, AES_GCM_KEY_USAGES);
  
  const aesAlg = AES_GCM_ENC();
  const ct = await cs.encrypt(aesAlg, ek, plaintext);

  return {
    pub: kpE.publicKey,
    iv: aesAlg.iv,
    ct: ct,
  };
}

/*
 * Arguments:
 *   ciphertext: The value to be decrypted, as an object
 *   priv:       Private key for the receiver
 *
 * Returns: Promise<ArrayBuffer>
 */
async function decrypt(ciphertext, priv) {
  const dhAlg = ECDH_DERIVE(ciphertext.pub);
  const ek = await cs.deriveKey(dhAlg, priv, AES_GCM_GEN, false, AES_GCM_KEY_USAGES);

  const aesAlg = AES_GCM_ENC(ciphertext.iv);
  return cs.decrypt(aesAlg, ek, ciphertext.ct);
}

/*
 * Self-test: Encrypt/decrypt round trip
 */
async function test() {
  let keyPair;
  const original = new Uint8Array([0,1,2,3]);

  const kp = await cs.generateKey(ECDH_GEN, false, ECDH_KEY_USAGES);

  try {
    const encrypted = await encrypt(original, kp.publicKey);
    const decrypted = await decrypt(encrypted, kp.privateKey);
    
    const equal = (Array.from(decrypted).filter((x,i) => (original[i] != x)).length == 0)
    console.log("[ECKEM]", equal? "PASS" : "FAIL");
  } catch (err) {
    console.log("[ECKEM] FAIL:", err);
  }
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
  test: test,
}
