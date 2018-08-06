'use strict'

const tm = require('./tree-math');

/*
 * This class represents a tree of public keys, e.g., one obtained
 * by scraping keys out of handshake messages.
 */
class Tree {
  constructor(size) {
    this.size = size;
    this.nodes = {};
  }

  merge(nodes) {
    Object.assign(this.nodes, nodes);
  }

  remove(index) {
    tm.dirpath(2 * index, this.size).map(n => {
      delete this.nodes[n];
    });
  }

  gatherSubtree(node) {
    let out = {};

    if (this.nodes[node]) {
      out[node] = this.nodes[node];
      return out;
    }

    let left = tm.left(node);
    if (left != node) {
      Object.assign(out, this.gatherSubtree(left));
    }
    
    let right = tm.right(node, this.size);
    if (right != node) {
      Object.assign(out, this.gatherSubtree(right));
    }

    return out;
  }

  copath(index) {
    return tm.copath(2 * index, this.size)
             .map(n => this.gatherSubtree(n))
             .reduce((a, b) => Object.assign(a, b), {});
  }
};

module.exports = Tree;
