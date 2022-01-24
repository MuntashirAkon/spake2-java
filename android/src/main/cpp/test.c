/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

#include<stdio.h>
#include<stdlib.h>

#include "sha512.c"
#include "spake25519.c"

static const uint8_t kPassword[70] = {
    0x35, 0x39, 0x32, 0x37, 0x38, 0x31, 0xe6, 0x3d, 0xd9, 0x59, 0x65, 0x1c,
    0x21, 0x16, 0x00, 0xf3, 0xb6, 0x56, 0x1d, 0x0b, 0x9d, 0x90, 0xaf, 0x09,
    0xd0, 0xa4, 0xa4, 0x53, 0xee, 0x20, 0x59, 0xa4, 0x80, 0xcc, 0x7c, 0x5a,
    0x94, 0xd4, 0xd4, 0x89, 0x33, 0xf9, 0xff, 0xf5, 0xfe, 0x43, 0x31, 0x7d,
    0x52, 0xfa, 0x7b, 0xff, 0x8f, 0x8b, 0xc4, 0xf3, 0x48, 0x8b, 0x80, 0x07,
    0x33, 0x0f, 0xec, 0x7c, 0x7e, 0xdc, 0x91, 0xc2, 0x0e, 0x5d,
};

static const uint8_t kClientName[] = "adb pair client";
static const uint8_t kServerName[] = "adb pair server";

int hexify(const uint8_t *in, size_t in_size, char *out, size_t out_size) {
    if (in_size == 0 || out_size == 0) return 0;

    char map[16+1] = "0123456789ABCDEF";

    int bytes_written = 0;
    size_t i = 0;
    while(i < in_size && (i*2 + (2+1)) <= out_size)
    {
        uint8_t high_nibble = (in[i] & 0xF0) >> 4;
        *out = map[high_nibble];
        out++;

        uint8_t low_nibble = in[i] & 0x0F;
        *out = map[low_nibble];
        out++;

        i++;

        bytes_written += 2;
    }
    *out = '\0';

    return bytes_written;
}

int main() {
    char output[300];
    uint8_t bytes[64];

    srand ((unsigned int) time (NULL));

    struct spake2_ctx_st *alice = SPAKE2_CTX_new(spake2_role_alice, kClientName, sizeof(kClientName), kServerName, sizeof(kServerName));
    struct spake2_ctx_st *bob = SPAKE2_CTX_new(spake2_role_bob, kServerName, sizeof(kServerName), kClientName, sizeof(kClientName));
    if (alice == NULL || bob == NULL) {
        printf("Unable to create a SPAKE2 context.");
        return 1;
    }

    uint8_t aMessage[32];
    uint8_t bMessage[32];
    size_t aMsgSize;
    size_t bMsgSize;

    int status = SPAKE2_generate_msg(alice, aMessage, &aMsgSize, 32, kPassword, sizeof(kPassword));
    status += SPAKE2_generate_msg(bob, bMessage, &bMsgSize, 32, kPassword, sizeof(kPassword));

    if (status != 2 || aMsgSize == 0 || bMsgSize == 0) {
        printf("Unable to generate the SPAKE2 public key.");
        return 1;
    }

    hexify(aMessage, 32, output, 65);
    printf("ALICE(%zu) ==> %s\n", aMsgSize, output);
    hexify(bMessage, 32, output, 65);
    printf("BOB(%zu)   ==> %s\n", bMsgSize, output);

    size_t aKeyLen = 0;
    uint8_t aKey[64];
    status = SPAKE2_process_msg(alice, aKey, &aKeyLen, sizeof(aKey), (uint8_t *) bMessage, bMsgSize);

    size_t bKeyLen = 0;
    uint8_t bKey[64];
    status += SPAKE2_process_msg(bob, bKey, &bKeyLen, sizeof(bKey), (uint8_t *) aMessage, aMsgSize);

    if (status != 2) {
        printf("Unable to process their public key");
        return 1;
    }

    hexify(aKey, 64, output, 129);
    printf("ALICE(%zu) <== %s\n", aKeyLen, output);
    hexify(bKey, 64, output, 129);
    printf("BOB(%zu)   <== %s\n", bKeyLen, output);
    return 0;
}
