'use strict';

module.exports = {
  stringify: function(a) {
    if (a instanceof ArrayBuffer) {
      a = new Uint8Array(a);
    }

    return btoa(String.fromCharCode.apply(0, a))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  },
  
  parse: function(s) {
    s = s.replace(/-/g, "+")
      .replace(/_/g, "/")
      .replace(/\s/g, '');
    let u = new Uint8Array(Array.prototype.map.call(atob(s), c => c.charCodeAt(0)));
    return u.buffer;
  },

  random: function(n) {
    const b = crypto.getRandomValues(new Uint8Array(n));
    return this.stringify(b);
  },
};
