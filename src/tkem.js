'use strict';

const ECKEM = require('./eckem');
const iota = require('./iota');
const tm = require('./tree-math');
const cs = window.crypto.subtle;

const SVG = require('svg.js');

function hex(ab) {
  const arr = Array.from(new Uint8Array(ab));
  return arr.map(x => ('0' + x.toString(16)).slice(-2)).join('');
}

async function fingerprint(pubKey) {
  const spki = await cs.exportKey("spki", pubKey);
  const digest = await cs.digest("SHA-256", spki);
  return hex(digest);
}

function hash(x) {
  return cs.digest("SHA-256", x);
}

const FADESTART = 20;
const FADESTOP = 80;

async function hashUp(index, size, h) {
  // Compute hashes up the tree
  let nodes = {};
  let n = index;
  let root = tm.root(size);
  let path = [n];
  while (true) {
    let kp = await iota(h);
    nodes[n] = {
      secret: h,
      public: kp.publicKey,
      private: kp.privateKey,
    };

    if (n == root) {
      break;
    }

    n = tm.parent(n, size);
    path.push(n);
    h = await hash(h);
  }

  // Colorize the nodes
  // #ifdef COLORIZE
  let height = tm.level(root);
  let hue = Array.from(new Uint8Array(nodes[root].secret)).reduce((x, y) => x ^ y);
  let dl = Math.round((FADESTOP - FADESTART) / height);
  for (let i = 0; i < path.length; ++i) {
    let l = FADESTART + i * dl;
    let color = `hsl(${hue}, 100%, ${l}%)`;
    nodes[path[path.length - i - 1]].color = color;
  }
  // #endif /* def COLORIZE */

  return nodes;
}

class TKEM {
  /*
   * TKEM objects should not be constructed directly.  Instead, use
   * the `TKEM.fromX` factory methods.  This only exists to give
   * certain variables public exposure for debugging, and as a base
   * for the factory methods.  It would be private in C++.
   */
  constructor() {
    this.size = 0;
    this.index = 0;
    this.nodes = [];
  }

  /*
   * Construct a TKEM representing a group with a single member,
   * with the given leaf secret.
   */
  static async oneMemberGroup(leaf) {
    let tkem = new TKEM();
    tkem.size = 1;
    tkem.index = 0;
    tkem.merge(await hashUp(0, 1, leaf));
    return tkem;
  }

  /*
   * Construct a tree that extends a tree with the given size and
   * frontier by adding a member with the given leaf secret.
   */
  static async fromFrontier(size, frontier, leaf) {
    let tkem = new TKEM();
    tkem.size = size + 1;
    tkem.index = size;
    tkem.merge(frontier);

    let nodes = await hashUp(2 * tkem.index, tkem.size, leaf);
    tkem.merge(nodes);
    return tkem;
  }

  /*
   * Encrypt a fresh root value in a way that all participants in
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
   *     // Public nodes along the direct path
   *     nodes: { Int: Node }
   *
   *     // Private nodes along the direct path
   *     privateNodes: { Int: Node }
   *
   *     // Ciphertexts along the copath
   *     ciphertexts: [ ECKEMCiphertext ]
   *   }
   */
  async encrypt(leaf) {
    let dirpath = tm.dirpath(2 * this.index, this.size);
    let copath = tm.copath(2 * this.index, this.size);
    
    // Generate hashes up the tree
    let privateNodes = await hashUp(2 * this.index, this.size, leaf);
    let nodes = {};
    for (let n in privateNodes) {
      nodes[n] = {
        public: privateNodes[n].public,
        // #ifdef COLORIZE
        color: privateNodes[n].color,
        // #endif /* def COLORIZE */
      }
    }

    // KEM each hash to the corresponding copath node
    let ciphertexts = await Promise.all(copath.map(async (c, i) => {
      let p = tm.parent(c, this.size);
      let s = privateNodes[p].secret;
      return ECKEM.encrypt(s, this.nodes[c].public);
    }));

    return {
      root: privateNodes[tm.root(this.size)].secret,
      index: this.index,
      size: this.size,
      nodes: nodes,
      privateNodes: privateNodes,
      ciphertexts: ciphertexts,
    }; 
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
   *     // Public nodes resulting from hashes on the direct path
   *     nodes: { Int: Node }
   *   }
   */
  async decrypt(index, ciphertexts) {
    // These are the nodes that the sender encrypted to
    let senderSize = (index == this.size)? this.size + 1 : this.size;
    let copath = tm.copath(2 * index, senderSize);

    // These are the nodes that we should have private keys for
    let dirpath = tm.dirpath(2 * this.index, this.size);
    dirpath.push(tm.root(this.size));

    // Decrypt at the point where the dirpath and copath overlap
    let overlap = dirpath.filter(x => copath.includes(x))[0];
    let coIndex = copath.indexOf(overlap);
    let dirIndex = dirpath.indexOf(overlap);
    let h = await ECKEM.decrypt(ciphertexts[coIndex], this.nodes[overlap].private);

    // Hash up to the root (plus one if we're growing the tree)
    let newDirpath = tm.dirpath(2 * this.index, senderSize);
    newDirpath.push(tm.root(senderSize));
    let nodes = await hashUp(newDirpath[dirIndex+1], senderSize, h);

    let root = tm.root(senderSize);
    return {
      root: nodes[root].secret,
      nodes: nodes,
    }
  }

  /*
   * Generate a UserAdd, which is just a FreshKey message with a
   * tree size one bigger than the current tree.  The resulting
   * message can be processed by decrypt().
   */
  static async userAdd(size, frontier, leaf) {
    let tkem = await TKEM.fromFrontier(size, frontier, leaf);
    return await tkem.encrypt(leaf);
  }

  /* 
   * Generate a GroupAdd, which has (1) a FreshKey message for current
   * members and (2) initialization information for the new member.
   */
  async groupAdd(leaf, initPub) {
    let freshKey = await TKEM.userAdd(this.size, this.frontier(), leaf);
    let encryptedLeaf = await ECKEM.encrypt(leaf, initPub);
    return {
      forGroup: freshKey,
      forJoiner: {
        size: this.size,
        frontier: this.frontier(),
        encryptedLeaf: encryptedLeaf,
      },
    }
  }

  /*
   * Updates nodes in the tree.
   *
   * Arguments:
   *   nodes - Dictionary of nodes to udpate: { Int: Node }
   *
   * Returns: None
   */
  merge(nodes) {
    for (let n in nodes) {
      this.nodes[n] = nodes[n];
    }
  }

  /*
   * Returns the nodes on the frontier of the tree { Int: Node }
   */
  frontier() {
    let nodes = {};
    for (let n of tm.frontier(this.size)) {
      nodes[n] = this.nodes[n];
    }
    return nodes;
  }

  /*
   * Trees are equal if they have the same shape and they agree in
   * the nodes where they overlap.  Since there's no direct way to
   * test equality of CryptoKey objects, we export the public key
   * and check for equality of the exported octets.
   */
  async equal(other) {
    async function nodeEqual(a, b) {
      return fingerprint(a.public) == fingerprint(b.public);
    }

    let answer = (this.size == other.size);

    for (let n in this.nodes) {
      let lhs = this.nodes[n];
      let rhs = other.nodes[n];
      if (!lhs || !rhs) {
        continue;
      }

      let lfp = await fingerprint(lhs.public);
      let rfp = await fingerprint(rhs.public);
      answer = answer && (lfp == rfp);

    }

    return answer;
  }

  async dump(label) {
    console.log("=====", label, "=====");
    console.log("size:", this.size);
    console.log("index:", this.index);
    console.log("nodes:");
    for (let n in this.nodes) {
      if (!this.nodes[n]) {
        continue;
      }

      console.log("  ", n, ":", await fingerprint(this.nodes[n].public));
    }
  }

  // #ifdef COLORIZE
  /********** SILLY DRAWING STUFF **********/

  /*
   * Draw an illustration of this tree as SVG into a <div>
   *
   * NB: Assumes:
   *   * `this.index` and `this.size` are set
   *   * No SVG is currently present in the indicated <div>
   */
  renderInit(id) {
    const root = tm.root(this.size);
    const height = tm.level(root);
    const width = tm.nodeWidth(this.size);
 
    const RECTRAD = 10;
    const RECTSIZE = 2 * RECTRAD;
    const RECTSPACE = 50;
    const STROKEWIDTH = 3;
 
    function center(n) {
      const h = tm.level(n);
      return {
        x: n * RECTSPACE + RECTRAD,
        y: (height - h) * RECTSPACE + RECTRAD,
      };
    }
 
    let index = [...Array(width).keys()];
    let nc = index.map(k => center(k));
    let pc = index.map(k => nc[tm.parent(k, this.size)]);

    this.svg = SVG(id).size(width * RECTSPACE, width * RECTSPACE);
    this.lines = index.map(k => {
      return this.svg.line(nc[k].x, nc[k].y, pc[k].x, pc[k].y)
                     .stroke({ width: STROKEWIDTH });
    });
    this.rects = index.map(k => {
      return this.svg.rect(RECTSIZE, RECTSIZE)
                     .cx(nc[k].x).cy(nc[k].y)
                     .stroke({ width: STROKEWIDTH });

    });

    return this;
  }

  async render() {
    const DEFAULTSTROKE = "hsl(0, 0%, 75%)";
    const DEFAULTFILL = "hsl(0, 0%, 100%)";

    async function hue(k) {
      let data = await cs.exportKey("spki", k);
      let hue = Array.from(new Uint8Array(data)).reduce((x, y) => x ^ y);
      return `hsl(${hue}, 100%, 50%)`;
    }

    let index = [...Array(this.rects.length).keys()];

    let stroke = await Promise.all(index.map(async k => {
      return (!this.nodes[k])? DEFAULTSTROKE
           : (this.nodes[k].color)? this.nodes[k].color
           : await hue(this.nodes[k].public);
    }));
 
    let fill = index.map(k => {
      return (this.nodes[k] && this.nodes[k].private)? stroke[k] : DEFAULTFILL;
    });

    this.lines.map((line, k) => { line.stroke(stroke[k]); });
    this.rects.map((rect, k) => { rect.fill(fill[k]).stroke(stroke[k]); });
  }
  // #endif /* def COLORIZE */
}

function arrayBufferEqual(a, b) {
  let ua = Array.from(new Uint8Array(a));
  let ub = Array.from(new Uint8Array(b));
  return ua.filter((x, i) => (ub[i] != x)).length == 0;
}

async function testMembers(size) {
  let nodeWidth = tm.nodeWidth(size);
  let keyPairs = await Promise.all([...Array(nodeWidth).keys()].map(i => iota(new Uint8Array([i]))));
  
  let nodes = {}
  keyPairs.map((kp, i) => { 
    nodes[i] = {
      private: kp.privateKey, 
      public: kp.publicKey 
    };
  });

  // Provision members
  let members = [];
  const root = tm.root(size);
  for (let i = 0; i < size; ++i) {
    members[i] = new TKEM();
    members[i].size = size;
    members[i].index = i;

    // Public keys along its copath
    for (const n of tm.copath(2*i, size)) {
      members[i].nodes[n] = {
        public: nodes[n].public,
      };
    }

    // Private keys along its direct path
    let dirpath = tm.dirpath(2*i, size);
    dirpath.push(root);
    for (const n of dirpath) {
      members[i].nodes[n] = {
        private: nodes[n].private,
        public: nodes[n].public,
      };
    }
  }

  return members;
}

async function testUserAdd() {
  const testGroupSize = 5;
  
  let creator = await TKEM.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];

  let size = creator.size;
  let frontier = creator.frontier();
  for (let i = 1; i < testGroupSize; ++i) {
    let leaf = new Uint8Array([i]);
    let ua = await TKEM.userAdd(size, frontier, leaf); 

    // Instantiate joiner
    let joiner = await TKEM.fromFrontier(size, frontier, leaf);

    // Update other members
    for (let m of members) {
      let pt = await m.decrypt(ua.index, ua.ciphertexts);
      m.merge(ua.nodes);
      m.merge(pt.nodes);
      m.size = ua.size;

      let eq = await joiner.equal(m);
      if (!eq) {
        throw 'tkem-eq';
      }
    }

    members.push(joiner);
    size = joiner.size;
    frontier = joiner.frontier();
  }

  console.log("[tkem-user-add] PASS")
}

async function testGroupAdd() {
  const testGroupSize = 5;
  
  let last = await TKEM.oneMemberGroup(new Uint8Array([0]));
  let members = [last];

  for (let i = 1; i < testGroupSize; ++i) {
    let leafIn = new Uint8Array([i]);
    let initKP = await iota(new Uint8Array([2]));
    let ga = await last.groupAdd(leafIn, initKP.publicKey);
    
    // Instantiate joiner
    let leaf = await ECKEM.decrypt(ga.forJoiner.encryptedLeaf, initKP.privateKey);
    let joiner = await TKEM.fromFrontier(ga.forJoiner.size, ga.forJoiner.frontier, leaf);

    // Update other members
    for (let m of members) {
      let pt = await m.decrypt(ga.forGroup.index, ga.forGroup.ciphertexts);
      m.merge(ga.forGroup.nodes);
      m.merge(pt.nodes);
      m.size = ga.forGroup.size;

      let eq = await joiner.equal(m);
      if (!eq) {
        throw 'tkem-eq';
      }
    }

    members.push(joiner);
    last = joiner;
  }

  console.log("[tkem-group-add] PASS")
}

async function testUpdate() {
  const testGroupSize = 5;

  // Values you should see on inspection:
  // h^0 = 00010203
  // h^1 = 054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8
  // h^2 = f7a355c00c89a08c80636bed35556a210b51786f6803a494f28fc5ba05959fc2
  // h^3 = b4e844306e22060209c2f63956ab8bd5266cb548472d6773ebb41eb5bd700173
  // h^4 = 858b98df0255fbd305d9b772e19159e3f92b5ed7a458c549040f4d6331b5ea19 <-- too far
  const seed = new Uint8Array([0,1,2,3]);

  // Create a group with the specified size
  let members = await testMembers(testGroupSize);

  // Have each member send and be received by all members
  for (const m of members) {
    let ct = await m.encrypt(seed);
    m.merge(ct.privateNodes);

    for (let m2 of members) {
      if (m2.index == m.index) {
        continue;
      }

      let pt = await m2.decrypt(ct.index, ct.ciphertexts);
      if (!arrayBufferEqual(ct.root, pt.root)) {
        console.log("error:", m.index, "->", m2.index);
        console.log("send:", hex(ct.root));
        console.log("recv:", hex(pt.root));
        throw 'tkem-root';
      }

      // Merge public values, then private
      m2.merge(ct.nodes);
      m2.merge(pt.nodes);

      let eq = await m.equal(m2);
      if (!eq) {
        console.log("error:", m.index, "->", m2.index);
        throw 'tkem-eq';
      }
    }
  }

  console.log("[tkem-encrypt-decrypt] PASS");
}

async function test() {
  await testUpdate();
  await testUserAdd();
  await testGroupAdd();
}

module.exports = {
  class: TKEM,
  testMembers: testMembers,
  testUpdate: testUpdate,
  testUserAdd: testUserAdd,
  testGroupAdd: testGroupAdd,
  test: test,
};
