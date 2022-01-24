/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

#ifndef _SHA512_H
#define _SHA512_H 1

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__)
#include <endian.h>
#elif __FreeBSD__
#include <sys/endian.h>
#elif defined(__APPLE__) && defined(__MACH__)
#include <machine/endian.h>
#else
#error Couldn't find any appropriate endian.h
#endif


/* Structure to save state of computation between the single steps.  */
struct sha512_ctx
{
  uint64_t H[8];

  union
  {
#define TOTAL128_low (1 - (BYTE_ORDER == LITTLE_ENDIAN))
#define TOTAL128_high (BYTE_ORDER == LITTLE_ENDIAN)
    uint64_t total[2];
  };
  uint64_t buflen;
  union
  {
    char buffer[256];
    uint64_t buffer64[32];
  };
};

/* Initialize structure containing state of computation.
   (FIPS 180-2: 5.3.3)  */
extern void __sha512_init_ctx (struct sha512_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 128.  */
extern void __sha512_process_bytes (const void *buffer, size_t len,
				    struct sha512_ctx *ctx);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 64 bytes following RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 64 bits value.  */
extern void *__sha512_finish_ctx (struct sha512_ctx *ctx, void *resbuf);

#endif /* sha512.h */
