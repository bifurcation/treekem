# TKEM for Group Key Management

This repo contains an implementation of a group key management
scheme based on key encryption (KEM) rather than DH.  In both the DH
and KEM cases, the participants are arranged in a tree.  The DH case
corresponds to [ART](https://eprint.iacr.org/2017/666).  Since we're
using KEM and a tree here, we call the approach TKEM.

Right now the implementation is verify incomplete.  It basically
just loads a couple of things into the browser that you can play
with.


## Quickstart

```
> npm install
> npm run build
> open index.html

# In browser console
> ECKEM.test();
> tm.test();
> TKEM.test();
```

The test methods should exercise basically all of the functionality.
Check them out to see what's actually going on here.


## TODO

- [x] ECIES + AES-GCM "KEM"
- [x] Transformation from bytes to EC key pairs ("iota")
- [x] Tree index math, ported from C++ / Go
- [x] TKEM encryption / decryption
- [ ] Constructor(s) for TKEM objects
- [ ] Updates to TKEM objects
- [ ] Merges between TKEM changes
