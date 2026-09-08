# Ill Bloom

Build:

```bash
cc -O3 -march=native -o illbloom_dump generate/illbloom_dump.c
```

Usage:

```bash
./illbloom_dump                                # 128-bit whole space -> /data/illbloom_full_space/illbloom.bin
./illbloom_dump 256                             # 256-bit whole space -> /data/illbloom_full_space/illbloom256.bin
./illbloom_dump selftest | selftest256          # verify the entropy fn against golden vectors
./illbloom_dump <state0> <state1> <outfile|--> [256]   # manual state range, either width
```
