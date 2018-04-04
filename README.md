TKEM for Group Key Management
=============================

This repo contains an implementation of a group key management
scheme based on key encryption (KEM) rather than DH.  In both the DH
and KEM cases, the participants are arranged in a tree.  The DH case
corresponds to [ART](https://eprint.iacr.org/2017/666).  Since we're
using KEM and a tree here, we call the approach TKEM.

Right now the implementation is verify incomplete.  It basically
just loads a couple of things into the browser that you can play
with.

```
> npm install
> npm run build
> open index.html
```
