# Coldcard Mk2/Mk3

Build:

```bash
cc -O3 -march=native -o coldcard_dump generate/coldcard_dump.c
```

Usage:

```bash
# whole space: each adv in {0,18} x {normal, scramble} -> coldcard_{normal,scramble}_a{0,18}.bin
./coldcard_dump

# manual range: pad-index [i0,i1) x touch[0,tmax) at a fixed adv -> file (or -- for compute-only)
./coldcard_dump <i0> <i1> <touchmax> <adv> <outfile|--> [normal|scramble]

# verify against golden vectors
./coldcard_dump selftest
```
