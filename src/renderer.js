'use strict'

const tm = require('./tree-math');
const SVG = require('svg.js');

const PAD = 1;
const RECTRAD = 5;
const RECTSPACE = 25;
const STROKEWIDTH = 2;
const RECTSIZE = 2 * RECTRAD;

const DEFAULTSTROKE = "#eee";
const DEFAULTFILL = "#fff";

const FADESTART = 30;
const FADESTOP = 70;

function center(n, height) {
  const h = tm.level(n);
  return {
    x: n * RECTSPACE + RECTRAD + PAD,
    y: (height - h) * RECTSPACE + RECTRAD + PAD,
  };
}

function resize(svg, width, height) {
  let w = (width-1) * RECTSPACE + RECTSIZE + 2 * PAD;
  let h = height * RECTSPACE + RECTSIZE + 2 * PAD;
  svg.size(w, h);
}

async function hue(k) {
  let data = await cs.exportKey("spki", k);
  let hue = Array.from(new Uint8Array(data)).reduce((x, y) => x ^ y);
  return `hsl(${hue}, 100%, 50%)`;
}

class Renderer {
  constructor(id) {
    this.svg = SVG(id);
    resize(this.svg, 0, 0);
    this.lineGroup = this.svg.group();
    this.rectGroup = this.svg.group();
    this.lines = [];
    this.rects = [];
  }

  async render(size, nodes) {
    const root = tm.root(size);
    const height = tm.level(root);
    const width = tm.nodeWidth(size);

    let index = [...Array(width).keys()];
    let nc = index.map(k => center(k, height));
    let pc = index.map(k => nc[tm.parent(k, size)]);

    // Add rectangles if needed
    resize(this.svg, width, height);
    while (this.rects.length < width) {
      let k = this.rects.length;

      let line = this.lineGroup.line(nc[k].x, nc[k].y, pc[k].x, pc[k].y)
                               .stroke({ width: STROKEWIDTH });

      let rect = this.rectGroup.rect(RECTSIZE, RECTSIZE)
                               .cx(nc[k].x).cy(nc[k].y)
                               .stroke({ width: STROKEWIDTH });

      this.lines.push(line);
      this.rects.push(rect);
    }

    // Move everything to the right position
    nc.map((c, k) => {
      this.rects[k].cx(nc[k].x).cy(nc[k].y);
      this.lines[k].plot(nc[k].x, nc[k].y, pc[k].x, pc[k].y);
    });

    // Apply colors
    let stroke = await Promise.all(index.map(async k => {
      return (!nodes[k])? DEFAULTSTROKE
           : (nodes[k].color)? nodes[k].color
           : await hue(nodes[k].public);
    }));

    let fill = index.map(k => {
      return (nodes[k] && nodes[k].private)? stroke[k] : DEFAULTFILL;
    });

    this.lines.map((line, k) => { line.stroke(stroke[k]); });
    this.rects.map((rect, k) => { rect.fill(fill[k]).stroke(stroke[k]); });
  }
}

module.exports = Renderer;
