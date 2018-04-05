function log2(x) {
  if (x == 0) {
    return 0;
  }

  return Math.floor(Math.log2(x));
}

function level(x) {
  if ((x & 0x01) == 0) {
    return 0;
  }

  k = 0;
  while (((x >> k) & 0x01) == 1) {
    k += 1;
  }
  return k;
}

function nodeWidth(n) {
  return 2 * (n - 1) + 1;
}

function root(n) {
  w = nodeWidth(n);
  return (1 << log2(w)) - 1;
}

function left(x) {
  if (level(x) == 0) {
    return x;
  }

  return x ^ (0x01 << (level(x) - 1));
}

function right(x, n) {
  if (level(x) == 0) {
    return x;
  }

  r = x ^ (0x03 << (level(x) - 1));
  while (r >= nodeWidth(n)) {
    r = left(r);
  }
  return r;
}

function parentStep(x) {
  const k = level(x);
  one = 1;
  return (x | (one << k)) & ~(one << (k + 1));
}

function parent(x, n) {
  if (x == root(n)) {
    return x;
  }

  let p = parentStep(x);
  while (p >= nodeWidth(n)) {
    p = parentStep(p);
  }
  return p;
}

function sibling(x, n) {
  const p = parent(x, n);
  if (x < p) {
    return right(p, n);
  } else if (x > p) {
    return left(p);
  }

  // root's sibling is itself
  return p;
}

// Ordered from leaf to root
// Includes leaf, but not root
function dirpath(x, n) {
  if (x == root(n)) {
    return [];
  }

  let d = [x];
  let p = parent(x, n);
  const r = root(n);
  while (p != r) {
    d.push(p);
    p = parent(p, n);
  }
  return d;
}

// Ordered from leaf to root
function copath(x, n) {
  return dirpath(x, n).map(x => sibling(x, n));
}

// Ordered from left to right
function frontier(n) {
  let last = 2*(n-1);
  let f = copath(last, n).reverse();

  if (f[f.length - 1] != last) {
    f.push(last);
  }

  while (f.length > 1) {
    let r = f[f.length - 1];
    let p = parent(r, n);
    if (p != parentStep(r)) {
      break;
    }

    // Replace the last two nodes with their parent
    f = f.slice(0, -2).concat(p);
  }
  
  return f;
}

function leaves(n) {
  return [...Array(n).keys()].map(x => 2*x);
}

/////

// Precomputed answers for the tree on eleven elements:
//
//                                               X
//                       X
//           X                       X                       X
//     X           X           X           X           X
//  X     X     X     X     X     X     X     X     X     X     X
// 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14

function arrayEqual(a, b) {
  return (a.length == b.length && a.filter((x, i) => (b[i] != x)).length == 0);
}

function testRoot() {
  const n = 0x0b;
  const index = [...Array(n).keys()];
  const aRoot = [ 0x00, 0x01, 0x03, 0x03, 0x07, 0x07,
                  0x07, 0x07, 0x0f, 0x0f, 0x0f ];

  let q = [...Array(n).keys()].map(x => root(x+1));
  if (!arrayEqual(q, aRoot)) {
    console.log("root", q, aRoot);
    throw "root";
  }

  console.log("[tree-root] PASS");
}

function testRelations() {
  const n = 0x0b;

  const index = [...Array(nodeWidth(n)).keys()];
  
  const aLeft = [ 0x00, 0x00, 0x02, 0x01, 0x04, 0x04, 0x06,
                  0x03, 0x08, 0x08, 0x0a, 0x09, 0x0c, 0x0c,
                  0x0e, 0x07, 0x10, 0x10, 0x12, 0x11, 0x14 ];
  
  const aRight = [ 0x00, 0x02, 0x02, 0x05, 0x04, 0x06, 0x06,
                   0x0b, 0x08, 0x0a, 0x0a, 0x0d, 0x0c, 0x0e,
                   0x0e, 0x13, 0x10, 0x12, 0x12, 0x14, 0x14 ];
  
  const aParent = [ 0x01, 0x03, 0x01, 0x07, 0x05, 0x03, 0x05,
                    0x0f, 0x09, 0x0b, 0x09, 0x07, 0x0d, 0x0b,
                    0x0d, 0x0f, 0x11, 0x13, 0x11, 0x0f, 0x13 ];
  
  const aSibling = [ 0x02, 0x05, 0x00, 0x0b, 0x06, 0x01, 0x04,
                     0x13, 0x0a, 0x0d, 0x08, 0x03, 0x0e, 0x09,
                     0x0c, 0x0f, 0x12, 0x14, 0x10, 0x07, 0x11 ];

  const cases = [
    { l: "left", f: left, a: aLeft },
    { l: "right", f: x => right(x, n), a: aRight },
    { l: "parent", f: x => parent(x, n), a: aParent },
    { l: "sibling", f: x => sibling(x, n), a: aSibling },
  ];

  for (c of cases) {
    let q = index.map(c.f);
    if (!arrayEqual(q, c.a)) {
      console.log(c.l, q, c.a);
      throw c.l;
    }
  }
  console.log("[tree-relations] PASS");
}

function testFrontier() {
  const n = 0x0b;

  const aFrontier = [
    [0x00],
    [0x01],
    [0x01, 0x04],
    [0x03],
    [0x03, 0x08],
    [0x03, 0x09],
    [0x03, 0x09, 0x0c],
    [0x07],
    [0x07, 0x10],
    [0x07, 0x11],
    [0x07, 0x11, 0x14],
  ];

  for (let x = 1; x <= n; x += 1) {
    let f = frontier(x);
    if (!arrayEqual(f, aFrontier[x-1])) {
      console.log('frontier', f, aFrontier[x-1]);
      throw 'frontier';
    }
  }
  
  console.log("[tree-frontier] PASS");
}

function testPaths() {
  const n = 0x0b;

  const aDirpath = [
    [0, 1, 3, 7],
    [1, 3, 7],
    [2, 1, 3, 7],
    [3, 7],
    [4, 5, 3, 7],
    [5, 3, 7],
    [6, 5, 3, 7],
    [7],
    [8, 9, 11, 7],
    [9, 11, 7],
    [10, 9, 11, 7],
    [11, 7],
    [12, 13, 11, 7],
    [13, 11, 7],
    [14, 13, 11, 7],
    [],
    [16, 17, 19],
    [17, 19],
    [18, 17, 19],
    [19],
    [20, 19]
  ];

  const aCopath = [
    [2, 5, 11, 19],
    [5, 11, 19],
    [0, 5, 11, 19],
    [11, 19],
    [6, 1, 11, 19],
    [1, 11, 19],
    [4, 1, 11, 19],
    [19],
    [10, 13, 3, 19],
    [13, 3, 19],
    [8, 13, 3, 19],
    [3, 19],
    [14, 9, 3, 19],
    [9, 3, 19],
    [12, 9, 3, 19],
    [],
    [18, 20, 7],
    [20, 7],
    [16, 20, 7],
    [7],
    [17, 7]
  ];

  for (let x = 0; x < nodeWidth(n); x += 1) {
    let d = dirpath(x, n);
    if (!arrayEqual(d, aDirpath[x])) {
      console.log('dirpath', d, aDirpath[x]);
      throw 'dirpath';
    }
    
    let c = copath(x, n);
    if (!arrayEqual(c, aCopath[x])) {
      console.log('copath', c, aCopath[x]);
      throw 'copath';
    }
  }
  
  console.log("[tree-paths] PASS");
}

function test() {
  testRoot();
  testRelations();
  testFrontier();
  testPaths();
}

// XXX(rlb@ipv.sx): This list can probably be pared down further.
// Not everything needs to be exposed.
module.exports = {
  // Basic tree properties
  nodeWidth: nodeWidth,
  root: root,
  
  // Node relations
  left: left,
  right: right,
  parent: parent,
  sibling: sibling,

  // Paths
  frontier: frontier,
  dirpath: dirpath,
  copath: copath,
  leaves: leaves,

  test: test,
}
