'use strict';

const iota = require('./iota');
const DH = require('./dh');

async function nodeEqual(lhs, rhs) {
  let lfp = await DH.fingerprint(lhs.public);
  let rfp = await DH.fingerprint(rhs.public);
  return (lfp == rfp);
}

/*
 * Compares to group structs for equality.  Each one must have
 * `size` and `nodes` attributes.  Structs are equal if they have
 * the same size and agree on overlapping nodes.
 */
async function groupEqual(lhs, rhs) {
  let answer = (lhs.size == rhs.size);

  for (let n in lhs.nodes) {
    let lhn = lhs.nodes[n];
    let rhn = rhs.nodes[n];
    if (!lhn || !rhn) {
      continue;
    }
    
    let eq = await nodeEqual(lhn, rhn);
    answer = answer && eq;
  }

  return answer;
}

/*
 * Dumps a human-readable representation of a group struct.
 */
async function groupDump(label, group) {
  console.log("=====", label, "=====");
  console.log("size:", group.size);
  console.log("index:", group.index);
  console.log("nodes:");
  for (let n in group.nodes) {
    if (!group.nodes[n]) {
      continue;
    }

    console.log("  ", n, ":", await DH.fingerprint(group.nodes[n].public));
  }
}


async function testUserAdd(State) {
  const testGroupSize = 5;

  let creator = await State.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];

  for (let i = 1; i < testGroupSize; ++i) {
    let leaf = window.crypto.getRandomValues(new Uint8Array(32));
    let gik = members[members.length - 1].groupInitKey;
    let uaIn = await State.join(leaf, gik);

    let uaEnc = JSON.stringify(uaIn);
    let ua = JSON.parse(uaEnc);

    let joiner = await State.fromUserAdd(leaf, ua, gik);
    
    for (let m of members) {
      await m.handleUserAdd(ua);

      let eq = await groupEqual(joiner, m);
      if (!eq) {
        await groupDump(joiner.index, joiner);
        await groupDump(m.index, m);
        throw 'state-user-add';
      }
    }

    members.push(joiner);
  }

  console.log("[state-user-add] PASS");
}

async function testGroupAdd(State) {
  const testGroupSize = 5;

  let creator = await State.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];

  for (let i = 1; i < testGroupSize; ++i) {
    let initLeaf = window.crypto.getRandomValues(new Uint8Array(4));
    let initKP = await iota(initLeaf)
    let gaIn = await members[members.length - 1].add(initKP.publicKey)

    let gaEnc = JSON.stringify(gaIn);
    let ga = JSON.parse(gaEnc);

    let joiner = await State.fromGroupAdd(initLeaf, ga);

    for (let m of members) {
      await m.handleGroupAdd(ga);

      let eq = await groupEqual(joiner, m);
      if (!eq) {
        await groupDump(joiner.index, joiner);
        await groupDump(m.index, m);
        throw 'state-group-add';
      }
    }

    members.push(joiner);
  }

  console.log("[state-group-add] PASS");
}

async function testUpdate(State) {
  // Create a group via GroupAdds
  const testGroupSize = 5;
  let creator = await State.oneMemberGroup(new Uint8Array([0]));
  let members = [creator];
  for (let i = 1; i < testGroupSize; ++i) {
    let initLeaf = window.crypto.getRandomValues(new Uint8Array(4));
    let initKP = await iota(initLeaf);
    let ga = await members[members.length - 1].add(initKP.publicKey)

    for (let m of members) {
      await m.handleGroupAdd(ga);
    }

    let joiner = await State.fromGroupAdd(initLeaf, ga);
    members.push(joiner);
  }

  // Have each member update and verify that others are consistent
  for (let m1 of members) {
    let leaf = crypto.getRandomValues(new Uint8Array(32));
    let updateIn = await m1.update(leaf);
    
    let updateEnc = JSON.stringify(updateIn);
    let update = JSON.parse(updateEnc);

    await m1.handleSelfUpdate(update, leaf);

    for (let m2 of members) {
      if (m2.index == m1.index) {
        continue
      }
        
      await m2.handleUpdate(update);

      let eq = await groupEqual(m1, m2);
      if (!eq) {
        await groupDump(m1.index, m1);
        await groupDump(m2.index, m2);
        throw 'state-group-add';
      }
    }
  }
  
  console.log("[state-update] PASS");
}

module.exports = {
  test: async function(State) {
    await testUserAdd(State);
    await testGroupAdd(State);
    await testUpdate(State);
  },
};
