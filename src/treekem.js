'use strict';

const ECKEM = require('./eckem');
const iota = require('./iota');
const tm = require('./tree-math');
const util = require('./util');
const dh = require('./dh');
const cs = window.crypto.subtle;

// #ifdef COLORIZE
const FADESTART = 30;
const FADESTOP = 70;
// #endif /* def COLORIZE */

function hex(ab) {
  const arr = Array.from(new Uint8Array(ab));
  return arr.map(x => ('0' + x.toString(16)).slice(-2)).join('');
}

function xor(a, b) {
  const ua = new Uint8Array(a);
  const ub = new Uint8Array(b);
  return (new Uint8Array(ua.map((x, i) => x ^ ub[i]))).buffer;
}

async function hash(x64) {
  const x = base64.parse(x64);
  const d = await cs.digest("SHA-256", x);
  return base64.stringify(d);
}

class TreeKEM {
  /*
   * TreeKEM objects should not be constructed directly.  Instead, use
   * the `TreeKEM.fromX` factory methods.  This only exists to give
   * certain variables public exposure for debugging, and as a base
   * for the factory methods.  It would be private in C++.
   */
  constructor() {
    this.size = 0;
    this.index = 0;
    this.nodes = [];
  }

  static fromJSON(obj) {
    let out = new TreeKEM();
    out.size = obj.size;
    out.index = obj.index;
    out.nodes = obj.nodes;
    return out;
  }

  /*
   * Construct a TreeKEM representing a group with a single member,
   * with the given leaf secret.
   */
  static async oneMemberGroup(leaf) {
    let tkem = new TreeKEM();
    tkem.size = 1;
    tkem.index = 0;
    tkem.merge(await TreeKEM.hashUp(0, 1, leaf));
    return tkem;
  }

  /*
   * Construct a tree that extends a tree with the given size and
   * frontier by adding a member with the given leaf secret.
   */
  static async fromFrontier(size, frontier, leaf) {
    let tkem = new TreeKEM();
    tkem.size = size + 1;
    tkem.index = size;
    tkem.merge(frontier);

    let nodes = await TreeKEM.hashUp(2 * tkem.index, tkem.size, leaf);
    tkem.merge(nodes);
    return tkem;
  }

  /* 
   * Map a function over the populated subtree heads beneath an
   * intermediate node.  Results are collated in an object whose
   * keys are the indices of the relevant tree nodes.
   *
   * Inputs:
   *  * node - Head of the subtree
   *  * func - func(nodeID) -> T
   *
   * Returns:
   *  * {Node: T}
   */
  mapSubtree(node, func) {
    let out = {};

    if (this.nodes[node]) {
      out[node] = func(node);
      return out;
    }

    let left = tm.left(node);
    if (left != node) {
      Object.assign(out, this.mapSubtree(left, func));
    }
    
    let right = tm.right(node, this.size);
    if (right != node) {
      Object.assign(out, this.mapSubtree(right, func));
    }

    return out;
  }

  /*
   * Encrypt a value so that it can be decrypted by all nodes in the
   * subtree with the indicated head, even if some leaves are
   * excluded.
   */
  async encryptToSubtree(head, value) {
    let encryptions = this.mapSubtree(head, async node => {
      return await ECKEM.encrypt(value, this.nodes[node].public);
    });

    for (let n in encryptions) {
      encryptions[n] = await encryptions[n];
    }
    return encryptions;
  }

  /*
   * Gather the heads of the populated subtrees below the specified
   * subtree head
   */
  gatherSubtree(head) {
    return this.mapSubtree(head, node => util.publicNode(this.nodes[node]));
  }

  /*
   * Encrypt a fresh root value in a way that all participants in
   * the group can decrypt, except for an excluded node.
   *
   * Arguments:
   *   * leaf - BufferSource with leaf secret
   *   * except - index of the node to exclude
   *
   * Returns: Promise resolving to a TreeKEMCiphertext object:
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
  async encrypt(leaf, except) {
    let dirpath = tm.dirpath(2 * except, this.size);
    let copath = tm.copath(2 * except, this.size);

    // Generate hashes up the tree
    let privateNodes = await TreeKEM.hashUp(2 * except, this.size, leaf);
    let nodes = {};
    for (let n in privateNodes) {
      nodes[n] = util.publicNode(privateNodes[n]);
    }

    // KEM each hash to the corresponding copath node
    let ciphertexts = await Promise.all(copath.map(async (c, i) => {
      let p = tm.parent(c, this.size);
      let s = privateNodes[p].secret;
      return this.encryptToSubtree(c, s);
    }));

    return {
      nodes: nodes,
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
    let encryptions = ciphertexts[coIndex];

    // Extract an encrypted value that we can decrypt, and decrypt it
    let decNode = Object.keys(encryptions)
                        .map(x => parseInt(x))
                        .filter(x => dirpath.includes(x))[0];

    let h = await ECKEM.decrypt(encryptions[decNode], this.nodes[decNode].private);

    // Hash up to the root (plus one if we're growing the tree)
    let rootNode = tm.root(senderSize);
    let newDirpath = tm.dirpath(2 * this.index, senderSize);
    newDirpath.push(rootNode);
    let nodes = await TreeKEM.hashUp(newDirpath[dirIndex+1], senderSize, h);

    let root = {}
    root[rootNode] = nodes[rootNode];

    return {
      root: root,
      nodes: nodes,
    }
  }

  /*
   * Removes unnecessary nodes from the tree when the size of the
   * group shrinks.
   */
  trim(size) {
    if (size > this.size) {
      throw "Cannot trim upwards";
    }

    let width = tm.nodeWidth(size);
    this.nodes = this.nodes.slice(0, width);
    this.size = size;
  }

  /* 
   * Remove a node from the tree, including its direct path
   *
   * Arguments:
   *   index - Index of the node to remove
   *
   * Returns: None
   */
  remove(index) {
    for (let n of tm.dirpath(2 * index, this.size)) {
      delete this.nodes[n];
    }
  }

  /*
   * Updates nodes in the tree.
   *
   * Arguments:
   *   nodes - Dictionary of nodes to update: { Int: Node }
   *   preserve - Whether existing nodes should be left alone
   *
   * Returns: None
   */
  merge(nodes, preserve) {
    for (let n in nodes) {
      if (this.nodes[n] && preserve) {
        continue;
      }
    
      this.nodes[n] = nodes[n];
    }
  }

  /*
   * Returns the nodes on the frontier of the tree { Int: Node },
   * including subtree heads if the tree is incomplete.
   */
  frontier() {
    return tm.frontier(this.size)
             .map(n => this.gatherSubtree(n))
             .reduce((a, b) => Object.assign(a, b), {});
  }

  /* 
   * Returns the nodes on the copath for this node { Int: Node },
   * including subtree heads if the tree is incomplete.
   */
  copath(index) {
    return tm.copath(2 * index, this.size)
             .map(n => this.gatherSubtree(n))
             .reduce((a, b) => Object.assign(a, b), {});
  }

  /*
   * Two instances are equal if they agree on the nodes where they
   * overlap.
   */
  async equal(other) {
    if (this.size != other.size) {
      return false;
    }

    for (let i in this.nodes) {
      if (!other.nodes[i]) {
        continue;
      }

      let fp1 = await dh.fingerprint(this.nodes[i].public);
      let fp2 = await dh.fingerprint(other.nodes[i].public);
      if (fp1 !== fp2) {
        return false;
      }
    }

    return true;
  }

  static async hashUp(index, size, h) {
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
  
    // #ifdef COLORIZE
    let height = tm.level(root) || 1;
    let secret = base64.parse(nodes[root].secret);
    let hue = Array.from(new Uint8Array(secret)).reduce((x, y) => x ^ y);
    let dl = Math.round((FADESTOP - FADESTART) / height);
    for (let i = 0; i < path.length; ++i) {
      let l = FADESTART + i * dl;
      nodes[path[path.length - i - 1]].color = [hue, 100, l];
    }
    // #endif /* def COLORIZE */
  
    return nodes;
  }

  async dump(label) {
    console.log("===== treekem dump (", label,") =====");
    console.log("size:", this.size);
    console.log("nodes:", this.nodes);
    for (let i in this.nodes) {
      console.log("  ", i, ":", await dh.fingerprint(this.nodes[i].public));
    }
  }
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
    members[i] = new TreeKEM();
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

async function testEncryptDecrypt() {
  const testGroupSize = 5;
  const seed = new Uint8Array([0,1,2,3]);

  // Create a group with the specified size
  let members = await testMembers(testGroupSize);

  // Have each member send and be received by all members
  for (const m of members) {
    let ct = await m.encrypt(seed);
    let privateNodes = await TreeKEM.hashUp(2 * m.index, m.size, seed);
 
    m.merge(ct.nodes)
    m.merge(privateNodes);

    for (let m2 of members) {
      if (m2.index == m.index) {
        continue;
      }

      let pt = await m2.decrypt(m.index, ct.ciphertexts);
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

async function testSimultaneousUpdate() {
  const testGroupSize = 5;
  let members = await testMembers(testGroupSize);

  // Have each member emit an update, then have everyone compute and
  // apply a merged update
  let seeds = members.map(m => new Uint8Array([m.index]));
  let cts = await Promise.all(members.map(m => {
    return m.encrypt(seeds[m.index]);
  }));

  let secrets = await Promise.all(members.map(async m => {
    let privateNodes = await TreeKEM.hashUp(2 * m.index, m.size, seeds[m.index]);

    const pts = (await Promise.all(cts.map((ct, i) => {
      return (i == m.index)? null : m.decrypt(i, ct.ciphertexts);
    })));

    // The secret for the merge will be the XOR of all the
    // individual root secrets
    const roots = pts.map((pt, i) => {
      return (i == m.index)? privateNodes[tm.root(m.size)] : pt.root;
    });
    let secret = roots.reduce(xor);
    
    // The key pair changes are applied in order of arrival
    for (let i = 0; i < pts.length; ++i) {
      if (i == m.index) {
        m.merge(privateNodes);
        continue;
      }

      m.merge(cts[i].nodes);
      m.merge(pts[i].nodes);
    }
    return secret;
  }));

  // Check that all of the derived secrets are the same
  secrets.reduce((a, b) => {
    if (!arrayBufferEqual(a, b)) {
      console.log("error:", hex(a), hex(b));
      throw 'tkem-simultaneous-secret';
    }

    return a;
  });

  // Check that all members arrived in the same state
  for (const m1 of members) {
    for (const m2 of members) {
      let eq = await m1.equal(m2);
      if (!eq) {
        console.log("error:", m1.index, "!=", m2.index);
        await m1.dump();
        await m2.dump();
        throw 'tkem-simultaneous-tree';
      }
    }
  }
   
  console.log("[tkem-simultaneous] PASS");
}

async function test() {
  await testEncryptDecrypt();
  await testSimultaneousUpdate();
}

module.exports = {
  class: TreeKEM,
  test: test,
};
