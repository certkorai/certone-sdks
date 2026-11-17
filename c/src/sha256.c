/*
 * SHA-256 (FIPS 180-4), self-contained so the SDK depends on nothing but libcurl.
 * Used to compute the run-at-source `input_digest` ("sha256:<hex>") over snapshot bytes.
 */
#include "internal.h"

#include <stdio.h>
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

static uint32_t rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}

static void compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    for (i = 0; i < 64; i++) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + K[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void certone_sha256_init(certone_sha256_ctx *ctx)
{
    static const uint32_t H0[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                   0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    memcpy(ctx->state, H0, sizeof H0);
    ctx->bit_count = 0;
    ctx->buffer_len = 0;
}

void certone_sha256_update(certone_sha256_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    if (len == 0) {
        return;
    }
    ctx->bit_count += (uint64_t)len * 8u;
    if (ctx->buffer_len > 0) {
        size_t take = 64 - ctx->buffer_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->buffer + ctx->buffer_len, p, take);
        ctx->buffer_len += take;
        p += take;
        len -= take;
        if (ctx->buffer_len < 64) {
            return;
        }
        compress(ctx->state, ctx->buffer);
        ctx->buffer_len = 0;
    }
    while (len >= 64) {
        compress(ctx->state, p);
        p += 64;
        len -= 64;
    }
    if (len > 0) {
        memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }
}

void certone_sha256_final(certone_sha256_ctx *ctx, uint8_t digest[CERTONE_SHA256_DIGEST_SIZE])
{
    uint64_t bits = ctx->bit_count;
    unsigned i;

    ctx->buffer[ctx->buffer_len++] = 0x80;
    if (ctx->buffer_len > 56) {
        memset(ctx->buffer + ctx->buffer_len, 0, 64 - ctx->buffer_len);
        compress(ctx->state, ctx->buffer);
        ctx->buffer_len = 0;
    }
    memset(ctx->buffer + ctx->buffer_len, 0, 56 - ctx->buffer_len);
    for (i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    compress(ctx->state, ctx->buffer);
    for (i = 0; i < 8; i++) {
        digest[4 * i] = (uint8_t)(ctx->state[i] >> 24);
        digest[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[4 * i + 3] = (uint8_t)ctx->state[i];
    }
    memset(ctx, 0, sizeof *ctx);
}

void certone_sha256(const void *data, size_t len, uint8_t digest[CERTONE_SHA256_DIGEST_SIZE])
{
    certone_sha256_ctx ctx;
    certone_sha256_init(&ctx);
    certone_sha256_update(&ctx, data, len);
    certone_sha256_final(&ctx, digest);
}

static void format_digest(const uint8_t digest[CERTONE_SHA256_DIGEST_SIZE],
                          char out[CERTONE_INPUT_DIGEST_SIZE])
{
    static const char hex[] = "0123456789abcdef";
    unsigned i;

    memcpy(out, "sha256:", 7);
    for (i = 0; i < CERTONE_SHA256_DIGEST_SIZE; i++) {
        out[7 + 2 * i] = hex[digest[i] >> 4];
        out[7 + 2 * i + 1] = hex[digest[i] & 0x0F];
    }
    out[CERTONE_INPUT_DIGEST_SIZE - 1] = '\0';
}

void certone_input_digest(const void *data, size_t len, char out[CERTONE_INPUT_DIGEST_SIZE])
{
    uint8_t digest[CERTONE_SHA256_DIGEST_SIZE];
    certone_sha256(data, len, digest);
    format_digest(digest, out);
}

certone_status certone_input_digest_file(const char *path, char out[CERTONE_INPUT_DIGEST_SIZE])
{
    certone_sha256_ctx ctx;
    uint8_t digest[CERTONE_SHA256_DIGEST_SIZE];
    unsigned char chunk[8192];
    FILE *f;
    size_t n;
    int failed;

    if (path == NULL || out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        return CERTONE_E_IO;
    }
    certone_sha256_init(&ctx);
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) {
        certone_sha256_update(&ctx, chunk, n);
    }
    failed = ferror(f);
    if (fclose(f) != 0) {
        failed = 1;
    }
    if (failed) {
        memset(&ctx, 0, sizeof ctx);
        return CERTONE_E_IO;
    }
    certone_sha256_final(&ctx, digest);
    format_digest(digest, out);
    return CERTONE_OK;
}
