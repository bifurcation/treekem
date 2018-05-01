# TreeKEM for Group Key Management

This repo contains an implementation of a group key management
scheme based on key encryption (KEM) rather than DH.  In both the DH
and KEM cases, the participants are arranged in a tree.  The DH case
corresponds to [ART](https://eprint.iacr.org/2017/666).  Since we're
using KEM and a tree here, we call the approach TreeKEM.

In the `src` folder, there are implementations of three different
group key agreement protocols: ART, TreeKEM, and a "flat" protocol
where everyone just stores / sends `O(N)` keys.  After building, you
can use `index.html` to exercise these protocols and see
visualizations of how they work.

## Quickstart

```
> npm install
> npm run build
> open index.html
# Use buttons to perform tree operations
```
