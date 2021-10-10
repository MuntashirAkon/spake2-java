/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

#include<assert.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "curve25519_32.h"

#define FE_NUM_LIMBS 10

typedef struct fe { uint32_t v[10]; } fe;

typedef struct fe_loose { uint32_t v[10]; } fe_loose;

static const fe d = {{
    56195235, 13857412, 51736253, 6949390, 114729, 24766616, 60832955, 30306712,
    48412415, 21499315
}};

static const fe sqrtm1 = {{
    34513072, 25610706, 9377949, 3500415, 12389472, 33281959, 41962654,
    31548777, 326685, 11406482
}};

static const fe d2 = {{
    45281625, 27714825, 36363642, 13898781, 229458, 15978800, 54557047,
    27058993, 29715967, 9444199
}};

// h = 0
static void fe_0(fe *h) {
  memset(h, 0, sizeof(fe));
}

static void fe_loose_0(fe_loose *h) {
  memset(h, 0, sizeof(fe_loose));
}

// h = 1
static void fe_1(fe *h) {
  memset(h, 0, sizeof(fe));
  h->v[0] = 1;
}

static void fe_loose_1(fe_loose *h) {
  memset(h, 0, sizeof(fe_loose));
  h->v[0] = 1;
}

// h = f
static void fe_copy(fe *h, const fe *f) {
  memmove(h, f, sizeof(fe));
}

static void fe_copy_lt(fe_loose *h, const fe *f) {
  memmove(h, f, sizeof(fe));
}

static void fe_frombytes_strict(fe *h, const uint8_t s[32]) {
  // |fiat_25519_from_bytes| requires the top-most bit be clear.
  assert((s[31] & 0x80) == 0);
  fiat_25519_from_bytes(h->v, s);
}

static void fe_frombytes(fe *h, const uint8_t s[32]) {
  uint8_t s_copy[32];
  memcpy(s_copy, s, 32);
  s_copy[31] &= 0x7f;
  fe_frombytes_strict(h, s_copy);
}

static void fe_tobytes(uint8_t s[32], const fe *f) {
  fiat_25519_to_bytes(s, f->v);
}

// h = f + g
// Can overlap h with f or g.
static void fe_add(fe_loose *h, const fe *f, const fe *g) {
  fiat_25519_add(h->v, f->v, g->v);
}

// h = f - g
// Can overlap h with f or g.
static void fe_sub(fe_loose *h, const fe *f, const fe *g) {
  fiat_25519_sub(h->v, f->v, g->v);
}

static void fe_carry(fe *h, const fe_loose* f) {
  fiat_25519_carry(h->v, f->v);
}

static void fe_mul_impl(uint32_t out[FE_NUM_LIMBS],
                        const uint32_t in1[FE_NUM_LIMBS],
                        const uint32_t in2[FE_NUM_LIMBS]) {
  fiat_25519_carry_mul(out, in1, in2);
}

static void fe_mul_ltt(fe_loose *h, const fe *f, const fe *g) {
  fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_llt(fe_loose *h, const fe_loose *f, const fe *g) {
  fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_ttt(fe *h, const fe *f, const fe *g) {
  fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_tlt(fe *h, const fe_loose *f, const fe *g) {
  fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_ttl(fe *h, const fe *f, const fe_loose *g) {
  fe_mul_impl(h->v, f->v, g->v);
}

static void fe_mul_tll(fe *h, const fe_loose *f, const fe_loose *g) {
  fe_mul_impl(h->v, f->v, g->v);
}

static void fe_sq_tl(fe *h, const fe_loose *f) {
  fiat_25519_carry_square(h->v, f->v);
}

static void fe_sq_tt(fe *h, const fe *f) {
  fiat_25519_carry_square(h->v, f->v);
}

// h = -f
static void fe_neg(fe_loose *h, const fe *f) {
  fiat_25519_opp(h->v, f->v);
}

// Replace (f,g) with (g,g) if b == 1;
// replace (f,g) with (f,g) if b == 0.
//
// Preconditions: b in {0,1}.
static void fe_cmov(fe_loose *f, const fe_loose *g, uint32_t b) {
  // Silence an unused function warning. |fiat_25519_selectznz| isn't quite the
  // calling convention the rest of this code wants, so implement it by hand.
  //
  // TODO(davidben): Switch to fiat's calling convention, or ask fiat to emit a
  // different one.
  (void)fiat_25519_selectznz;

  b = 0-b;
  for (unsigned i = 0; i < FE_NUM_LIMBS; i++) {
    uint32_t x = f->v[i] ^ g->v[i];
    x &= b;
    f->v[i] ^= x;
  }
}

static void fe_copy_ll(fe_loose *h, const fe_loose *f) {
  memmove(h, f, sizeof(fe_loose));
}

static void fe_loose_invert(fe *out, const fe_loose *z) {
  fe t0;
  fe t1;
  fe t2;
  fe t3;
  int i;

  fe_sq_tl(&t0, z);
  fe_sq_tt(&t1, &t0);
  for (i = 1; i < 2; ++i) {
    fe_sq_tt(&t1, &t1);
  }
  fe_mul_tlt(&t1, z, &t1);
  fe_mul_ttt(&t0, &t0, &t1);
  fe_sq_tt(&t2, &t0);
  fe_mul_ttt(&t1, &t1, &t2);
  fe_sq_tt(&t2, &t1);
  for (i = 1; i < 5; ++i) {
    fe_sq_tt(&t2, &t2);
  }
  fe_mul_ttt(&t1, &t2, &t1);
  fe_sq_tt(&t2, &t1);
  for (i = 1; i < 10; ++i) {
    fe_sq_tt(&t2, &t2);
  }
  fe_mul_ttt(&t2, &t2, &t1);
  fe_sq_tt(&t3, &t2);
  for (i = 1; i < 20; ++i) {
    fe_sq_tt(&t3, &t3);
  }
  fe_mul_ttt(&t2, &t3, &t2);
  fe_sq_tt(&t2, &t2);
  for (i = 1; i < 10; ++i) {
    fe_sq_tt(&t2, &t2);
  }
  fe_mul_ttt(&t1, &t2, &t1);
  fe_sq_tt(&t2, &t1);
  for (i = 1; i < 50; ++i) {
    fe_sq_tt(&t2, &t2);
  }
  fe_mul_ttt(&t2, &t2, &t1);
  fe_sq_tt(&t3, &t2);
  for (i = 1; i < 100; ++i) {
    fe_sq_tt(&t3, &t3);
  }
  fe_mul_ttt(&t2, &t3, &t2);
  fe_sq_tt(&t2, &t2);
  for (i = 1; i < 50; ++i) {
    fe_sq_tt(&t2, &t2);
  }
  fe_mul_ttt(&t1, &t2, &t1);
  fe_sq_tt(&t1, &t1);
  for (i = 1; i < 5; ++i) {
    fe_sq_tt(&t1, &t1);
  }
  fe_mul_ttt(out, &t1, &t0);
}

static void fe_invert(fe *out, const fe *z) {
  fe_loose l;
  fe_copy_lt(&l, z);
  fe_loose_invert(out, &l);
}

// return 0 if f == 0
// return 1 if f != 0
static int fe_isnonzero(const fe_loose *f) {
  fe tight;
  fe_carry(&tight, f);
  uint8_t s[32];
  fe_tobytes(s, &tight);

  static const uint8_t zero[32] = {0};
  return memcmp(s, zero, sizeof(zero)) != 0;
}

// return 1 if f is in {1,3,5,...,q-2}
// return 0 if f is in {0,2,4,...,q-1}
static int fe_isnegative(const fe *f) {
  uint8_t s[32];
  fe_tobytes(s, f);
  return s[0] & 1;
}

static void fe_sq2_tt(fe *h, const fe *f) {
  // h = f^2
  fe_sq_tt(h, f);

  // h = h + h
  fe_loose tmp;
  fe_add(&tmp, h, h);
  fe_carry(h, &tmp);
}

static void fe_pow22523(fe *out, const fe *z) {
  fe t0;
  fe t1;
  fe t2;
  int i;

  fe_sq_tt(&t0, z);
  fe_sq_tt(&t1, &t0);
  for (i = 1; i < 2; ++i) {
    fe_sq_tt(&t1, &t1);
  }
  fe_mul_ttt(&t1, z, &t1);
  fe_mul_ttt(&t0, &t0, &t1);
  fe_sq_tt(&t0, &t0);
  fe_mul_ttt(&t0, &t1, &t0);
  fe_sq_tt(&t1, &t0);
  for (i = 1; i < 5; ++i) {
    fe_sq_tt(&t1, &t1);
  }
  fe_mul_ttt(&t0, &t1, &t0);
  fe_sq_tt(&t1, &t0);
  for (i = 1; i < 10; ++i) {
    fe_sq_tt(&t1, &t1);
  }
  fe_mul_ttt(&t1, &t1, &t0);
  fe_sq_tt(&t2, &t1);
  for (i = 1; i < 20; ++i) {
    fe_sq_tt(&t2, &t2);
  }
  fe_mul_ttt(&t1, &t2, &t1);
  fe_sq_tt(&t1, &t1);
  for (i = 1; i < 10; ++i) {
    fe_sq_tt(&t1, &t1);
  }
  fe_mul_ttt(&t0, &t1, &t0);
  fe_sq_tt(&t1, &t0);
  for (i = 1; i < 50; ++i) {
    fe_sq_tt(&t1, &t1);
  }
  fe_mul_ttt(&t1, &t1, &t0);
  fe_sq_tt(&t2, &t1);
  for (i = 1; i < 100; ++i) {
    fe_sq_tt(&t2, &t2);
  }
  fe_mul_ttt(&t1, &t2, &t1);
  fe_sq_tt(&t1, &t1);
  for (i = 1; i < 50; ++i) {
    fe_sq_tt(&t1, &t1);
  }
  fe_mul_ttt(&t0, &t1, &t0);
  fe_sq_tt(&t0, &t0);
  for (i = 1; i < 2; ++i) {
    fe_sq_tt(&t0, &t0);
  }
  fe_mul_ttt(out, &t0, z);
}

// ge means group element.
//
// Here the group is the set of pairs (x,y) of field elements (see fe.h)
// satisfying -x^2 + y^2 = 1 + d x^2y^2
// where d = -121665/121666.
//
// Representations:
//   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   ge_precomp (Duif): (y+x,y-x,2dxy)

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe_loose X;
  fe_loose Y;
  fe_loose Z;
  fe_loose T;
} ge_p1p1;

typedef struct {
  fe_loose yplusx;
  fe_loose yminusx;
  fe_loose xy2d;
} ge_precomp;

typedef struct {
  fe_loose YplusX;
  fe_loose YminusX;
  fe_loose Z;
  fe_loose T2d;
} ge_cached;


static void ge_p2_0(ge_p2 *h) {
  fe_0(&h->X);
  fe_1(&h->Y);
  fe_1(&h->Z);
}

static void ge_p3_0(ge_p3 *h) {
  fe_0(&h->X);
  fe_1(&h->Y);
  fe_1(&h->Z);
  fe_0(&h->T);
}

static void ge_cached_0(ge_cached *h) {
  fe_loose_1(&h->YplusX);
  fe_loose_1(&h->YminusX);
  fe_loose_1(&h->Z);
  fe_loose_0(&h->T2d);
}

static void ge_precomp_0(ge_precomp *h) {
  fe_loose_1(&h->yplusx);
  fe_loose_1(&h->yminusx);
  fe_loose_0(&h->xy2d);
}

// r = p
static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p) {
  fe_copy(&r->X, &p->X);
  fe_copy(&r->Y, &p->Y);
  fe_copy(&r->Z, &p->Z);
}

// r = p
void x25519_ge_p3_to_cached(ge_cached *r, const ge_p3 *p) {
  fe_add(&r->YplusX, &p->Y, &p->X);
  fe_sub(&r->YminusX, &p->Y, &p->X);
  fe_copy_lt(&r->Z, &p->Z);
  fe_mul_ltt(&r->T2d, &p->T, &d2);
}

// r = p
void x25519_ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p) {
  fe_mul_tll(&r->X, &p->X, &p->T);
  fe_mul_tll(&r->Y, &p->Y, &p->Z);
  fe_mul_tll(&r->Z, &p->Z, &p->T);
}

// r = p
void x25519_ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p) {
  fe_mul_tll(&r->X, &p->X, &p->T);
  fe_mul_tll(&r->Y, &p->Y, &p->Z);
  fe_mul_tll(&r->Z, &p->Z, &p->T);
  fe_mul_tll(&r->T, &p->X, &p->Y);
}

// r = p
static void ge_p1p1_to_cached(ge_cached *r, const ge_p1p1 *p) {
  ge_p3 t;
  x25519_ge_p1p1_to_p3(&t, p);
  x25519_ge_p3_to_cached(r, &t);
}

// r = 2 * p
static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p) {
  fe trX, trZ, trT;
  fe t0;

  fe_sq_tt(&trX, &p->X);
  fe_sq_tt(&trZ, &p->Y);
  fe_sq2_tt(&trT, &p->Z);
  fe_add(&r->Y, &p->X, &p->Y);
  fe_sq_tl(&t0, &r->Y);

  fe_add(&r->Y, &trZ, &trX);
  fe_sub(&r->Z, &trZ, &trX);
  fe_carry(&trZ, &r->Y);
  fe_sub(&r->X, &t0, &trZ);
  fe_carry(&trZ, &r->Z);
  fe_sub(&r->T, &trT, &trZ);
}

void x25519_ge_tobytes(uint8_t s[32], const ge_p2 *h) {
  fe recip;
  fe x;
  fe y;

  fe_invert(&recip, &h->Z);
  fe_mul_ttt(&x, &h->X, &recip);
  fe_mul_ttt(&y, &h->Y, &recip);
  fe_tobytes(s, &y);
  s[31] ^= fe_isnegative(&x) << 7;
}

static void ge_p3_tobytes(uint8_t s[32], const ge_p3 *h) {
  fe recip;
  fe x;
  fe y;

  fe_invert(&recip, &h->Z);
  fe_mul_ttt(&x, &h->X, &recip);
  fe_mul_ttt(&y, &h->Y, &recip);
  fe_tobytes(s, &y);
  s[31] ^= fe_isnegative(&x) << 7;
}

// r = p + q
static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q) {
  fe trY, trZ, trT;

  fe_add(&r->X, &p->Y, &p->X);
  fe_sub(&r->Y, &p->Y, &p->X);
  fe_mul_tll(&trZ, &r->X, &q->yplusx);
  fe_mul_tll(&trY, &r->Y, &q->yminusx);
  fe_mul_tlt(&trT, &q->xy2d, &p->T);
  fe_add(&r->T, &p->Z, &p->Z);
  fe_sub(&r->X, &trZ, &trY);
  fe_add(&r->Y, &trZ, &trY);
  fe_carry(&trZ, &r->T);
  fe_add(&r->Z, &trZ, &trT);
  fe_sub(&r->T, &trZ, &trT);
}

// r = p - q
static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q) {
  fe trY, trZ, trT;

  fe_add(&r->X, &p->Y, &p->X);
  fe_sub(&r->Y, &p->Y, &p->X);
  fe_mul_tll(&trZ, &r->X, &q->yminusx);
  fe_mul_tll(&trY, &r->Y, &q->yplusx);
  fe_mul_tlt(&trT, &q->xy2d, &p->T);
  fe_add(&r->T, &p->Z, &p->Z);
  fe_sub(&r->X, &trZ, &trY);
  fe_add(&r->Y, &trZ, &trY);
  fe_carry(&trZ, &r->T);
  fe_sub(&r->Z, &trZ, &trT);
  fe_add(&r->T, &trZ, &trT);
}

// r = p + q
void x25519_ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q) {
  fe trX, trY, trZ, trT;

  fe_add(&r->X, &p->Y, &p->X);
  fe_sub(&r->Y, &p->Y, &p->X);
  fe_mul_tll(&trZ, &r->X, &q->YplusX);
  fe_mul_tll(&trY, &r->Y, &q->YminusX);
  fe_mul_tlt(&trT, &q->T2d, &p->T);
  fe_mul_ttl(&trX, &p->Z, &q->Z);
  fe_add(&r->T, &trX, &trX);
  fe_sub(&r->X, &trZ, &trY);
  fe_add(&r->Y, &trZ, &trY);
  fe_carry(&trZ, &r->T);
  fe_add(&r->Z, &trZ, &trT);
  fe_sub(&r->T, &trZ, &trT);
}

// r = p - q
void x25519_ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q) {
  fe trX, trY, trZ, trT;

  fe_add(&r->X, &p->Y, &p->X);
  fe_sub(&r->Y, &p->Y, &p->X);
  fe_mul_tll(&trZ, &r->X, &q->YminusX);
  fe_mul_tll(&trY, &r->Y, &q->YplusX);
  fe_mul_tlt(&trT, &q->T2d, &p->T);
  fe_mul_ttl(&trX, &p->Z, &q->Z);
  fe_add(&r->T, &trX, &trX);
  fe_sub(&r->X, &trZ, &trY);
  fe_add(&r->Y, &trZ, &trY);
  printf("BEFORE: ");
  for (int i = 0; i < 10; ++i) printf("%d ", r->T.v[i]);
  printf("\n");
  fe_carry(&trZ, &r->T);
  printf("AFTER: ");
  for (int i = 0; i < 10; ++i) printf("%d ", trZ.v[i]);
  printf("\n");
  fe_sub(&r->Z, &trZ, &trT);
  fe_add(&r->T, &trZ, &trT);
}

int x25519_ge_frombytes_vartime(ge_p3 *h, const uint8_t s[32]) {
  fe u;
  fe_loose v;
  fe v3;
  fe vxx;
  fe_loose check;

  fe_frombytes(&h->Y, s);
  fe_1(&h->Z);
  fe_sq_tt(&v3, &h->Y);
  fe_mul_ttt(&vxx, &v3, &d);
  fe_sub(&v, &v3, &h->Z);  // u = y^2-1
  fe_carry(&u, &v);
  fe_add(&v, &vxx, &h->Z);  // v = dy^2+1

  fe_sq_tl(&v3, &v);
  fe_mul_ttl(&v3, &v3, &v);  // v3 = v^3
  fe_sq_tt(&h->X, &v3);
  fe_mul_ttl(&h->X, &h->X, &v);
  fe_mul_ttt(&h->X, &h->X, &u);  // x = uv^7

  fe_pow22523(&h->X, &h->X);  // x = (uv^7)^((q-5)/8)
  fe_mul_ttt(&h->X, &h->X, &v3);
  fe_mul_ttt(&h->X, &h->X, &u);  // x = uv^3(uv^7)^((q-5)/8)

  fe_sq_tt(&vxx, &h->X);
  fe_mul_ttl(&vxx, &vxx, &v);
  fe_sub(&check, &vxx, &u);
  if (fe_isnonzero(&check)) {
    fe_add(&check, &vxx, &u);
    if (fe_isnonzero(&check)) {
      return 0;
    }
    fe_mul_ttt(&h->X, &h->X, &sqrtm1);
  }

  if (fe_isnegative(&h->X) != (s[31] >> 7)) {
    fe_loose t;
    fe_neg(&t, &h->X);
    fe_carry(&h->X, &t);
  }

  fe_mul_ttt(&h->T, &h->X, &h->Y);
  return 1;
}
