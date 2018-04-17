'use strict';

const iota = require('./iota');
const cs = window.crypto.subtle;

// #ifdef COLORIZE
async function keyColor(k) {
  let data = await cs.exportKey("spki", k);
  let hue = Array.from(new Uint8Array(data)).reduce((x, y) => x ^ y);
  return [hue, 100, 50];
}

/*
function modAverage(x, y, m) {
  if (y < x) { 
    [x, y] = [y, x];
  }

  let aSide = (y - x)/2;
  let bSide = ((x + m) - y)/2;
  if (aSide < bSide) {
    return (x + aSide) % m;
  } else {
    return (y + bSide) % m;
  }
}

function colorAvg(c1, c2) {
  return [
    modAverage(c1[0], c2[0], 256),
    (c1[1] + c2[1]) / 2,
    (c1[2] + c2[2]) / 2,
  ];
}
*/

// RGB/HSL conversion adapted from StackOverflow
// https://stackoverflow.com/questions/2353211/hsl-to-rgb-color-conversion
function hue2rgb(p, q, t){
    if(t < 0) t += 1;
    if(t > 1) t -= 1;
    if(t < 1/6) return p + (q - p) * 6 * t;
    if(t < 1/2) return q;
    if(t < 2/3) return p + (q - p) * (2/3 - t) * 6;
    return p;
}

function hslToRgb(h, s, l){
    var r, g, b;

    if (s == 0) {
        r = g = b = l; // achromatic
    } else {
        var q = l < 0.5 ? l * (1 + s) : l + s - l * s;
        var p = 2 * l - q;
        r = hue2rgb(p, q, h + 1/3);
        g = hue2rgb(p, q, h);
        b = hue2rgb(p, q, h - 1/3);
    }

    return [r, g, b];
}

function rgbToHsl(r, g, b){
    let max = Math.max(r, g, b);
    let min = Math.min(r, g, b);
    let h, s, l = (max + min) / 2;

    if (max == min) {
        h = s = 0; // achromatic
    }else{
        var d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch(max){
            case r: h = (g - b) / d + (g < b ? 6 : 0); break;
            case g: h = (b - r) / d + 2; break;
            case b: h = (r - g) / d + 4; break;
        }
        h /= 6;
    }

    return [h, s, l];
}

function colorAvg(c1, c2) {
  let [h1, s1, l1] = [c1[0] / 255, c1[1] / 100, c1[2] / 100];
  let [h2, s2, l2] = [c2[0] / 255, c2[1] / 100, c2[2] / 100];
 
  let rgb1 = hslToRgb(h1, s1, l1);
  let rgb2 = hslToRgb(h2, s2, l2);
  let [ra, ga, ba] = rgb1.map((x, i) => (x + rgb2[i]) / 2);

  let [ha, sa, la] = rgbToHsl(ra, ga, ba);
  return [255 * ha, 100 * sa, 100 * la];
}
// #endif /* def COLORIZE */

async function newNode(secret) {
  let kp = await iota(secret);
  let color = await keyColor(kp.publicKey);
  return {
    secret: secret,
    private: kp.privateKey,
    public: kp.publicKey,
    color: color,
  };
}

function publicNode(node) {
  return {
    public: node.public,
    color: node.color,
  }
}

function nodePath(nodes, path) {
  let out = {};
  for (let n of path) {
    out[n] = publicNode(nodes[n]);
  }
  return out;
}

module.exports = {
  keyColor: keyColor,
  colorAvg: colorAvg,
  newNode: newNode,
  publicNode: publicNode,
  nodePath: nodePath,
}

