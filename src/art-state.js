'use strict';

//const ART = require('./art');
const iota = require('./iota');

class ARTState {
  constructor() {
  }

  async equal(other) {
  }

  async dump(label) {
  }  

  static async oneMemberGroup(leaf) {
    let state = ARTState();
    state.art = ART.oneMemberGroup(leaf);
    return state;
  }

  static async fromGroupAdd(initLeaf, groupAdd) {
    let initKP = await iota(initLeaf);
    let leaf = DH.secret(initKP.privatKey, groupAdd.forJoiner.ephemeral);

    let state = ARTState();
    state.art = ART.fromFrontier(groupAdd.forJoiner.size, groupAdd.forJoiner.frontier, leaf);
    return state;
  }

  static async fromUserAdd(leaf, /* IGNORED */ userAdd, groupInitKey) {
    let state = ARTState();
    state.art = ART.fromFrontier(groupInitKey.size, groupInitKey.frontier, leaf);
    return state;
  }

  static async join(leaf, groupInitKey) {
    let art = ART.fromFrontier(groupInitKey.size, groupInitKey.frontier);
    art.add(leaf);
    return {
      path: art.dirpath(art.size - 1),
    }
  }

  async add(userInitPub) {
    let kp = DH.newKeyPair();
    let leaf = DH.secret(kp.privateKey, userInitPub);

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
    let path = this.art.updatePath(leaf);
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
    this.art.merge(ua.path);
    this.art.build(ua.path);
  }

  async handleGroupAdd(ga) {
    this.art.size += 1;
    this.art.merge(ga.forGroup.path);
    this.art.build(ga.forGroup.path);
  }

  async handleSelfUpdate(/* IGNORED */ update, leaf) {
    this.art.setOwnLeaf(leaf);
  }

  async handleUpdate(update) {
    this.art.merge(update.path);
    this.art.build(update.path);
  }
  
  handleRemove(remove) {/* TODO */}
}

module.exports = ARTState;
