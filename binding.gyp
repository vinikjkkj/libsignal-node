{
  "targets": [{
    "target_name": "signal_crypto",
    "cflags!": [ "-fno-exceptions" ],
    "cflags_cc!": [ "-fno-exceptions" ],
    "sources": [
      "./native/curve25519-donna.c",
      "./native/ed25519/additions/compare.c",
      "./native/ed25519/additions/curve_sigs.c",
      "./native/ed25519/additions/sign_modified.c",
      "./native/ed25519/fe_0.c",
      "./native/ed25519/fe_1.c",
      "./native/ed25519/fe_add.c",
      "./native/ed25519/fe_cmov.c",
      "./native/ed25519/fe_copy.c",
      "./native/ed25519/fe_frombytes.c",
      "./native/ed25519/fe_invert.c",
      "./native/ed25519/fe_isnegative.c",
      "./native/ed25519/fe_isnonzero.c",
      "./native/ed25519/fe_mul.c",
      "./native/ed25519/fe_neg.c",
      "./native/ed25519/fe_pow22523.c",
      "./native/ed25519/fe_sq.c",
      "./native/ed25519/fe_sq2.c",
      "./native/ed25519/fe_sub.c",
      "./native/ed25519/fe_tobytes.c",
      "./native/ed25519/ge_add.c",
      "./native/ed25519/ge_double_scalarmult.c",
      "./native/ed25519/ge_frombytes.c",
      "./native/ed25519/ge_madd.c",
      "./native/ed25519/ge_msub.c",
      "./native/ed25519/ge_p1p1_to_p2.c",
      "./native/ed25519/ge_p1p1_to_p3.c",
      "./native/ed25519/ge_p2_0.c",
      "./native/ed25519/ge_p2_dbl.c",
      "./native/ed25519/ge_p3_0.c",
      "./native/ed25519/ge_p3_dbl.c",
      "./native/ed25519/ge_p3_to_cached.c",
      "./native/ed25519/ge_p3_to_p2.c",
      "./native/ed25519/ge_p3_tobytes.c",
      "./native/ed25519/ge_precomp_0.c",
      "./native/ed25519/ge_scalarmult_base.c",
      "./native/ed25519/ge_sub.c",
      "./native/ed25519/ge_tobytes.c",
      "./native/ed25519/open.c",
      "./native/ed25519/sc_muladd.c",
      "./native/ed25519/sc_reduce.c",
      "./native/ed25519/sign.c",
      "./native/ed25519/sha512/sha2big.c",
      "./native/ed25519/sha512/crypto_hash_sha512.c",
      "./src/crypto_binding.cpp"
    ],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")",
      "native/ed25519/nacl_includes",
      "native/ed25519",
      "native/ed25519/sha512"
    ],
    "defines": [ 
      "NAPI_DISABLE_CPP_EXCEPTIONS",
      "SPH_UPTR",
      "SPH_UNALIGNED",
      "SPH_BIG_ENDIAN=0",
      "SPH_LITTLE_ENDIAN=1",
      "SPH_SPARCV9_GCC_32",
      "SPH_SMALL_FOOTPRINT=0",
      "SPH_64"
    ]
  }]
}