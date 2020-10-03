# spake2

[RFC](https://tools.ietf.org/html/draft-irtf-cfrg-spake2-13)

Dependencies:

1. Cloudflare's [CIRCL](https://github.com/cloudflare/circl) - For P384 (amd64) and Ed448 

2. Scrypt and Argon2id are given as MHF options. (see spake2.go)


**!!NOT FOR PROD!!**

This is for benchmarking purposes only.

It doesn't have the Per-user M & N from the RFC.

```
goarch: amd64
pkg: github.com/jtejido/spake2
BenchmarkSPAKE2Ed25519Scrypt-4              1411            724337 ns/op
BenchmarkSPAKE2Ed448Scrypt-4                 573           1842925 ns/op
BenchmarkSPAKE2P256Sha256Scrypt-4           1332            887259 ns/op
BenchmarkSPAKE2P384Sha256Scrypt-4            282           4471907 ns/op
BenchmarkSPAKE2P256Sha512Scrypt-4           1275            962927 ns/op
BenchmarkSPAKE2P384Sha512Scrypt-4            276           4286376 ns/op
PASS
```