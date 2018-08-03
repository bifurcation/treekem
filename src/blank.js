'use strict';

const tm = require('./tree-math.js');

let state = {
  size: 0,
  nodes: [],
  known: [],

  hasPriv: function(i, priv) {
    return this.known[i].filter(x => priv.startsWith(x)).length > 0;
  }
}

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

module.exports = {
  dump: function dump() {
    console.log("=====");
    console.log("Size:", state.size);
    console.log("Nodes:");
    for (let i=0; i<tm.nodeWidth(state.size); ++i) {
      let level = tm.level(i);
      let pad = "   ".repeat(level)
      let contents = (state.nodes[i])? formatNode(state.nodes[i]) : "_";
      console.log(`  ${pad}${contents}`); 
    }

    console.log("Known:");
    for (let i=0; i<state.size; ++i) {
      console.log(`  ${i}: ${state.known[i].join(' ')}`);
    }
  },

  alloc: function alloc(size) {
    state.size = size;

    while (state.nodes.length < tm.nodeWidth(size)) {
      state.nodes.push(null);
    }

    while (state.known.length < size) {
      state.known.push([]);
    }
  },

  set: function set(k, val) {
    let dirpath = tm.dirpath(2*k, state.size);
    dirpath.push(tm.root(state.size));

    let old = dirpath.map(n => state.nodes[n]);

    dirpath.map((n, i) => {
      let node = createNode(val, i);
      state.nodes[n] = node; 

      let L = tm.left(n), R = tm.right(n, state.size);
      let child = (dirpath.includes(L))? R : L;
      if (!state.nodes[child]) {
        return;
      }

      let childPriv = state.nodes[child].priv;
      let oldPriv = (old[i])? old[i].priv : null;
      for (let i in state.known) {
        if (!state.hasPriv(i, childPriv)) {
          continue;
        }

        state.known[i].push(node.priv);

        let oldi = state.known[i].indexOf(oldPriv);
        if (oldi > -1) {
          state.known[i].splice(oldi, 1);
        }
      }
    });

    state.known[k].push(val);
    let oldPriv = (old[0])? old[0].priv : null;
    let oldi = state.known[k].indexOf(oldPriv);
    if (oldi > -1) {
      state.known[k].splice(oldi, 1);
    }
  },

  // A nodes private key is held by a leaf iff it that leaf is in
  // the shadow of the node
  verify: function verify() {
    for (let n in state.nodes) {
      if (!state.nodes[n]) {
        continue;
      }

      n = parseInt(n);
      let priv = state.nodes[n].priv;
      let shadow = tm.shadow(n, state.size).filter(x => !(x & 1)).map(x => x/2);
      let hasPriv = [...Array(state.size).keys()].filter(i => state.hasPriv(i, priv));

      let shadowSet = {};
      for (let x of shadow) {
        shadowSet[x] = true;
      }
      for (let x of hasPriv) {
        if (!shadowSet[x]) {
          return false;
        }
      }
    }
    
    return true;
  },

  test: function test() {
    this.alloc(7);
    this.set(0, 'a');
    this.set(1, 'b');
    this.set(2, 'c');
    this.dump();
    console.log(this.verify());
  },
};




