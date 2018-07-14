'use strict';

const DH = require('./dh');
const tm = require('./tree-math');
const util = require('./util');

class ART {
  /*
   * ART objects should not be constructed directly.  Instead, use
   * the `ART.fromX` factory methods.  This only exists to give
   * certain variables public exposure for debugging, and as a base
   * for the factory methods.  It would be private in C++.
   */
  constructor() {
    this.size = 0;
    this.index = 0;
    this.nodes = [];
  }

  static fromJSON(obj) {
    let out = new ART();
    out.size = obj.size;
    out.index = obj.index;
    out.nodes = obj.nodes;
    return out;
  }

  /*
   * Construct an ART representing a group with a single member,
   * with the given leaf secret.
   */
  static async oneMemberGroup(leaf) {
    let art = new ART();
    art.size = 1;
    art.index = 0;
    await art.setOwnLeaf(leaf);
    return art;
  }

  /*
   * Construct a tree that extends a tree with the given size and
   * frontier by adding a member with the given leaf secret.
   */
  static async fromFrontier(size, frontier, leaf) {
    let art = new ART();
    art.size = size + 1;
    art.index = size;
    await art.merge(frontier);
    await art.setOwnLeaf(leaf)
    return art;
  }

  /*
   * Updates the leaf node corresponding to the holder of this tree
   */
  async setOwnLeaf(leaf) {
    let node = await util.newNode(leaf);
    let nodes = {};
    nodes[2 * this.index] = node;
    await this.merge(nodes);
  }

  /*
   * Updates nodes in the tree.  This proceeds in two stages:
   *   1. Copy the nodes into the tree
   *   2. Update any nodes above the changed nodes
   *
   * Arguments:
   *   nodes - Dictionary of nodes to udpate: { Int: Node }
   *
   * Returns: None
   */
  async merge(nodes) {
    let toUpdate = {};
    for (let n in nodes) {
      this.nodes[n] = nodes[n];

      const p = tm.parent(n, this.size);
      toUpdate[p] = true;
    }

    while (Object.keys(toUpdate).length > 0) {
      let nextToUpdate = {};

      for (let p in toUpdate) {
        let l = tm.left(p);
        let r = tm.right(p, this.size);
        if ((l == p) || (r == p)) {
          continue;
        }
      
        if (!this.nodes[l] || !this.nodes[r]) {
          continue;
        }

        let secret;
        if (this.nodes[l].private) {
          secret = await DH.secret(this.nodes[l].private, this.nodes[r].public);
        } else if (this.nodes[r].private) {
          secret = await DH.secret(this.nodes[r].private, this.nodes[l].public);
        } else {
          continue;
        }

        this.nodes[p] = await util.newNode(secret);

        // #ifdef COLORIZE
        this.nodes[p].color = util.colorAvg(this.nodes[l].color, this.nodes[r].color);
        // #endif /* def COLORIZE */
      
        const pp = tm.parent(p, this.size);
        if (pp != p) {
          nextToUpdate[pp] = true;
        }
      }

      toUpdate = nextToUpdate;
    }
  }

  /* 
   * Returns the nodes along the dirpath from this tree's leaf to
   * the root.
   */
  dirpath() {
    return util.nodePath(this.nodes, tm.dirpath(2 * this.index, this.size));
  }

  /*
   * Returns the nodes on the frontier of the tree { Int: Node }
   */
  frontier() {
    return util.nodePath(this.nodes, tm.frontier(this.size));
  }

  /*
   * Returns the path to the root from our leaf, assuming we replace
   * our leaf with the provided leaf.
   */
  async updatePath(leaf) {
    let art = new ART();
    art.size = this.size;
    art.index = this.index;
    art.merge(this.nodes);
    await art.setOwnLeaf(leaf);
    return art.dirpath();
  }
}

module.exports = {
  class: ART,
}
