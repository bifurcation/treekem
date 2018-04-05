'use strict';

const ECKEM = require('./eckem');
const iota = require('./iota');
const tm = require('./tree-math');
const cs = window.crypto.subtle;

function hash(x) {
  return cs.digest("SHA-256", x);
}

class TKEM {
  constructor(/* TODO */) {}

  /*
   * Encrypts a fresh root value in a way that all participants in
   * the group can decrypt (except for the current node).
   *
   * Arguments:
   *   * leaf - BufferSource with leaf secret
   *
   * Returns: Promise resolving to a TKEMCiphertext object:
   *   {
   *     // Index of the sender in the tree
   *     index: Int
   *
   *     // Public keys along the direct path
   *     publicKeys: [ CryptoKey ]
   *
   *     // Ciphertexts along the copath
   *     ciphertexts: [ ECKEMCiphertext ]
   *   }
   */
  encrypt(leaf) {
    let dirpath = tm.dirpath(2 * this.index, this.size);
    let copath = tm.copath(2 * this.index, this.size);
    
    let hashes = [];
    let publicKeys = [];
    let ciphertexts = [];

    // Generate hashes up the tree
    let p = Promise.resolve(leaf);
    for (let i = 0; i < dirpath.length; ++i) {
      p = p.then(hash)
       .then(h => {
         hashes[i] = h;
         return h;
       });
    }

    // For each hash:
    // * convert to public key
    // * KEM to corresponding copath node
    p = p.then(() => {
      return Promise.all(hashes.map((hash, i) => {
        return iota(hash)
          .then(kp => { publicKeys[i] = kp.publicKey })
          .then(() => {
            return ECKEM.encrypt(hash, this.nodes[copath[i]].public);
          })
          .then(ct => { ciphertexts[i] = ct; });
      }));
    })

    return p.then(() => { 
      return {
        root: hashes[hashes.length - 1],
        index: this.index,
        publicKeys: publicKeys,
        ciphertexts: ciphertexts,
      }; 
    });
  }

  /*
   * Decrypts and returns fresh root value.
   *
   * Arguments:
   *   * index       - Index of sending node in the tree
   *   * ciphertexts - List of ECKEMCiphertexts along copath
   *
   * Returns: Promise resolving to an object:
   *   {
   *     // The root hash for the tree
   *     root: ArrayBuffer
   *
   *     // Hashes for other nodes
   *     hashes: { Int: ArrayBuffer }
   *   }
   */
  decrypt(index, ciphertexts) {
    let dirpath = tm.dirpath(2 * this.index, this.size);
    let copath = tm.copath(2 * index, this.size);

    // Decrypt at the point where the dirpath and copath overlap
    let overlap = dirpath.filter(x => copath.includes(x))[0];
    let coIndex = copath.indexOf(overlap);
    let dirIndex = dirpath.indexOf(overlap);
    let p = ECKEM.decrypt(ciphertexts[coIndex], this.nodes[overlap].private);

    // Hash up to the root
    let hashes = {};
    let root = tm.root(this.size);
    dirpath.push(root);
    dirpath.slice(dirIndex+1).map((n, i) => {
      p = p.then(val => {
        hashes[n] = val;
        
        // Save the extra hash past the root
        return (n == root)? null : hash(val);
      });
    });

    return p.then(() => { 
      return {
        root: hashes[root],
        hashes: hashes,
      }   
    });
  }

  /*
   * Updates public keys along a path.
   *
   * Arguments:
   *   * index      - Index of sending node in the tree
   *   * publicKeys - List of CryptoKey values along direct path
   */
  update(index, publicKeys) {
    let dirpath = tm.dirpath(index, this.size);
    dirpath.map((n, i) => { this.nodes[n].public = publicKeys[i]; });
  }
}

function arrayBufferEqual(a, b) {
  let ua = Array.from(new Uint8Array(a));
  let ub = Array.from(new Uint8Array(b));
  return ua.filter((x, i) => (ub[i] != x)).length == 0;
}

function test() {
  let size = 5;
  let nodeWidth = tm.nodeWidth(size);
  let members = [];
  for (let i = 0; i < size; ++i) {
    members[i] = new TKEM();
    members[i].size = size;
    members[i].index = i;
  }


  let seed = new Uint8Array([0,1,2,3]);
  // h^1 = 054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8
  // h^2 = f7a355c00c89a08c80636bed35556a210b51786f6803a494f28fc5ba05959fc2
  // h^3 = b4e844306e22060209c2f63956ab8bd5266cb548472d6773ebb41eb5bd700173
  // h^4 = 858b98df0255fbd305d9b772e19159e3f92b5ed7a458c549040f4d6331b5ea19 <-- too far

  // Generate key pairs for all the tree nodes
  let p = Promise.all([...Array(nodeWidth).keys()].map(i => iota(new Uint8Array([i]))))
    .then(keyPairs => {
      let nodes = keyPairs.map(kp => {
        return { private: kp.privateKey, public: kp.publicKey };
      });

      members.map(x => { x.nodes = nodes; });
    });

  // Have each member send and be received by all members
  members.map((m, i) => {
    p = p.then(() => m.encrypt(seed))
      .then(ct => {

        return Promise.all(members.map(m2 => {
          if (m2.index == m.index) {
            return Promise.resolve(true);
          }

          return m2.decrypt(ct.index, ct.ciphertexts)
            .then(pt => {
              if (!arrayBufferEqual(ct.root, pt.root)) {
                console.log("error:", m.index, "->", m2.index);
                throw 'tkem';
              }
            })
        }));
      });
  });

  return p.then(() => { console.log("[tkem-encrypt-decrypt] PASS"); });
}

module.exports = {
  class: TKEM,
  test: test,
};
