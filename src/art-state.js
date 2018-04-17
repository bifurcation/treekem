'use strict';

const ART = require('./art').class;
const iota = require('./iota');

class ARTState {
  constructor() {
    this.art = null;
  }

  get index() {
    return this.art.index;
  }

  get size() {
    return this.art.size;
  }

  get nodes() {
    return this.art.nodes;
  }

  static async oneMemberGroup(leaf) {
    let state = new ARTState();
    state.art = await ART.oneMemberGroup(leaf);
    return state;
  }

  static async fromGroupAdd(initLeaf, groupAdd) {
    let initKP = await iota(initLeaf);
    let leaf = await DH.secret(initKP.privateKey, groupAdd.forJoiner.ephemeral);

    let state = new ARTState();
    state.art = await ART.fromFrontier(groupAdd.forJoiner.size, groupAdd.forJoiner.frontier, leaf);
    return state;
  }

  static async fromUserAdd(leaf, /* IGNORED */ userAdd, groupInitKey) {
    let state = new ARTState();
    state.art = await ART.fromFrontier(groupInitKey.size, groupInitKey.frontier, leaf);
    return state;
  }

  static async join(leaf, groupInitKey) {
    let art = await ART.fromFrontier(groupInitKey.size, groupInitKey.frontier, leaf);
    return {
      path: art.dirpath(art.size - 1),
    }
  }

  async add(userInitPub) {
    let kp = await DH.newKeyPair();
    let leaf = await DH.secret(kp.privateKey, userInitPub);

    let gik = this.groupInitKey;
    let ua = await ARTState.join(leaf, gik);

    return {
      forGroup: ua,
      forJoiner: { 
        size: gik.size,
        frontier: gik.frontier,
        ephemeral: kp.publicKey,
      },
    };
  }

  async update(leaf) {
    let path = await this.art.updatePath(leaf);
    return { path: path };
  }
  
  remove(index) {/* TODO */}

  get groupInitKey() {
    return {
      size: this.art.size,
      frontier: this.art.frontier(),
    };
  }

  async handleUserAdd(ua) {
    this.art.size += 1;
    await this.art.merge(ua.path);
  }

  async handleGroupAdd(ga) {
    this.art.size += 1;
    await this.art.merge(ga.forGroup.path);
  }

  async handleSelfUpdate(/* IGNORED */ update, leaf) {
    await this.art.setOwnLeaf(leaf);
  }

  async handleUpdate(update) {
    await this.art.merge(update.path);
  }
  
  handleRemove(remove) {/* TODO */}
}

module.exports = ARTState;
