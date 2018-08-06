'use strict';

const tm = require('./tree-math.js');

function createNode(val, i) {
  let priv = val + 'x'.repeat(i);
  return {
    priv: priv,
    pub: priv.toUpperCase(),
  };
}

function formatNode(node) {
  return `(${node.priv}, ${node.pub})`;
}

// Have to extend Array with a non-enumerable property so that
// for-in / for-of loops work properly
Object.defineProperty(Array.prototype, 'remove', {
  enumerable: false,
  value: function(val) {
    if (this.includes(val)) {
      this.splice(this.indexOf(val), 1);
    }
  },
});

Object.defineProperty(Array.prototype, 'addUnique', {
  enumerable: false,
  value: function(val) {
    if (!this.includes(val)) {
      this.push(val);
    }
  },
});

class Tree {
  constructor(size) {
    this.size = size || 0;

    this.nodes = [];
    while (this.nodes.length < tm.nodeWidth(this.size)) {
      this.nodes.push(null);
    }

    this.known = [];
    while (this.known.length < this.size) {
      this.known.push([]);
    }
  }

  hasPriv(i, priv) {
    return this.known[i].filter(x => priv.startsWith(x)).length > 0;
  }

  dump() {
    console.log("=====");
    console.log("Size:", this.size);
    console.log("Nodes:");
    for (let i=0; i<tm.nodeWidth(this.size); ++i) {
      let level = tm.level(i);
      let pad = "   ".repeat(level)
      let contents = (this.nodes[i])? formatNode(this.nodes[i]) : "_";
      console.log(`  ${pad}${contents}`); 
    }

    console.log("Known:");
    for (let i=0; i<this.size; ++i) {
      console.log(`  ${i}: ${this.known[i].join(' ')}`);
    }
  }

  sendPriv(priv, newVal, oldVal) {
    let recv = [];
    for (let i in this.known) {
      if (!this.hasPriv(i, priv)) {
        continue;
      }

      recv.push(i);
      this.known[i].push(newVal);
      this.known[i].remove(oldVal);
    }
  }

  send(n, newVal, oldVal) {
    if (this.nodes[n]) {
      this.sendPriv(this.nodes[n].priv, newVal, oldVal);
      return;
    }

    let L = tm.left(n);
    if (this.nodes[L]) {
      this.send(L, newVal, oldVal);
    }

    let R = tm.right(n, this.size);
    if (this.nodes[R]) {
      this.send(R, newVal, oldVal);
    }
  }

  set(k, val) {
    let dirpath = tm.dirpath(2*k, this.size);
    dirpath.push(tm.root(this.size));

    let old = dirpath.map(n => this.nodes[n]);

    dirpath.map((n, i) => {
      this.nodes[n] = createNode(val, i); 
      if (i == 0) {
        return
      }

      let L = tm.left(n), R = tm.right(n, this.size);
      let child = (dirpath.includes(L))? R : L;
      let newPriv = this.nodes[n].priv;
      let oldPriv = (old[i])? old[i].priv : null;
      this.send(child, newPriv, oldPriv);
    });

    let oldPriv = (old[0])? old[0].priv : null;
    if (!oldPriv) {
      this.known[k].push(val);
    } else {
      this.sendPriv(oldPriv, val, oldPriv);
    }
  }

  unset(k, val) {
    let dirpath = tm.dirpath(2*k, this.size);
    for (let n of dirpath) {
      delete this.nodes[n];
    }

    if (val) {
      let r = tm.root(this.size);
      let oldPriv = this.nodes[r].priv;
      this.nodes[r] = createNode(val, 0);
      this.send(r, val, oldPriv);
    }
  }

  move(src, dst, val) {
    this.unset(src);
    this.set(dst, val);
  }

  // A node's private key is held by a leaf iff :
  // * the leaf is in the shadow of the node, and
  // * the leaf is not blank
  verify() {
    for (let n in this.nodes) {
      if (!this.nodes[n]) {
        continue;
      }

      n = parseInt(n);
      let priv = this.nodes[n].priv;
      let shadow = tm.shadow(n, this.size)
                     .filter(x => !(x & 1))
                     .filter(x => !!this.nodes[x])
                     .map(x => x/2);
      let hasPriv = [...Array(this.size).keys()].filter(i => this.hasPriv(i, priv));

      let shadowSet = {};
      for (let x of shadow) {
        shadowSet[x] = true;
      }
      for (let x of hasPriv) {
        if (!shadowSet[x]) {
          console.log(priv, ':', shadow, '!=', hasPriv);
          return false;
        }
      }
    }
    
    return true;
  }
}

function fill(tree) {
  for (let i = 0; i < tree.size; i += 1) {
    let val = String.fromCharCode('a'.charCodeAt(0) + i);
    tree.set(i, val);
  }
  return tree;
}

function testSet() {
  let tree = new Tree(7);
  fill(tree);
  console.log('[set]', tree.verify());
}

function testUnset() {
  let tree = new Tree(7);
  fill(tree);

  tree.unset(3, 'r');
  tree.unset(2, 's');
  tree.unset(1, 't');
  
  console.log('[unset]', tree.verify());
}

function testReset() {
  let tree = new Tree(7);
  fill(tree);

  tree.unset(2, 'h');
  tree.set(0, 'i');
  tree.set(6, 'j');
  
  console.log('[reset]', tree.verify());
}

function testMove() {
  let tree = new Tree(7);
  fill(tree);
  
  tree.unset(3, 'r');
  tree.unset(2, 's');
  tree.unset(1, 't');

  tree.move(4, 1, 'h');
  tree.move(5, 2, 'i');
  tree.move(6, 3, 'j'); 
  
  console.log('[move]', tree.verify());
}

function testChaos() {
  let rounds = 200;
  let branches = 3;
  let size = 63;

  let tree = new Tree(size);
  let all = [...Array(size).keys()];
  let unset = [...Array(size).keys()];
  let set = [];
  let rand = (arr) => arr[Math.floor(Math.random() * arr.length)];
  let move = (val, src, dst) => {
    src.remove(val);
    dst.addUnique(val);
  };

  let base = 'a'.charCodeAt(0);
  let val = 0;
  let next = () => String.fromCharCode(base + val++);

  let doSet = () => {
    if (unset.length == 0) {
      return true;
    }

    let i = rand(all);
    tree.set(i, next());
    move(i, unset, set);
    return false;
  };

  let doUnset = () => {
    if (set.length == 0) {
      return true;
    }

    let i = rand(set);
    tree.unset(i, next());
    move(i, set, unset);
    return false;
  };

  let doMove = () => {
    if (set.length == 0 || unset.length == 0) {
      return true;
    }

    let src = rand(set);
    let dst = rand(unset);
    tree.move(src, dst, next());
    move(src, set, unset);
    move(dst, unset, set);
    return false;
  };

  let start = Date.now();

  // Initialize the tree about half-full
  while (set.length / tree.size < 0.5) {
    doSet();
  }

  for (let i = 0; i < rounds; ++i) {
    let roll = Math.floor(Math.random() * branches);
    
    let reroll = true;
    switch (roll) {
      case 0: reroll = doSet(); break;
      case 1: reroll = doUnset(); break;
      case 2: reroll = doMove(); break;
    }

    if (!tree.verify()) {
      console.log('[chaos] fail');
      return;
    }

    if (reroll) {
      i--;
    }
  }

  let finish = Date.now();
  let elapsed = (finish - start) / 1000;
  console.log(`[chaos] pass in ${elapsed} sec`);
}

module.exports = {
  Tree: Tree,

  // node -e "require('./blank').test()"
  test: function test() {
    testSet();
    testUnset();
    testReset();
    testMove();
    testChaos();
  },
};




