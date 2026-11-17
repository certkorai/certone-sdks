/* Offline tests for SHA-256 (FIPS 180-4 / NIST CAVP known-answer vectors) and input_digest. */
#include "certone.h"
#include "test_util.h"

static void to_hex(const uint8_t *d, size_t n, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i] = hex[d[i] >> 4];
        out[2 * i + 1] = hex[d[i] & 0x0F];
    }
    out[2 * n] = '\0';
}

static void check_vector(const char *msg, size_t len, const char *expected_hex)
{
    uint8_t d[CERTONE_SHA256_DIGEST_SIZE];
    char hex[2 * CERTONE_SHA256_DIGEST_SIZE + 1];
    certone_sha256(msg, len, d);
    to_hex(d, sizeof d, hex);
    CHECK_STR(hex, expected_hex);
}

static void test_known_vectors(void)
{
    check_vector("", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_vector("abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_vector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    check_vector("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopq"
                 "klmnopqrlmnopqrsmnopqrstnopqrstu",
                 112, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    check_vector("The quick brown fox jumps over the lazy dog", 43,
                 "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
}

static void test_million_a(void)
{
    certone_sha256_ctx ctx;
    uint8_t d[CERTONE_SHA256_DIGEST_SIZE];
    char hex[2 * CERTONE_SHA256_DIGEST_SIZE + 1];
    char block[1000];
    int i;

    memset(block, 'a', sizeof block);
    certone_sha256_init(&ctx);
    for (i = 0; i < 1000; i++) {
        certone_sha256_update(&ctx, block, sizeof block);
    }
    certone_sha256_final(&ctx, d);
    to_hex(d, sizeof d, hex);
    CHECK_STR(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

/* Every length around the padding boundaries, fed in uneven chunks, matches the one-shot. */
static void test_incremental_matches_one_shot(void)
{
    unsigned char msg[300];
    size_t len;
    size_t i;

    for (i = 0; i < sizeof msg; i++) {
        msg[i] = (unsigned char)(i * 31 + 7);
    }
    for (len = 0; len <= sizeof msg; len++) {
        uint8_t one[CERTONE_SHA256_DIGEST_SIZE];
        uint8_t inc[CERTONE_SHA256_DIGEST_SIZE];
        certone_sha256_ctx ctx;
        size_t off = 0;
        size_t step = 1;
        certone_sha256(msg, len, one);
        certone_sha256_init(&ctx);
        while (off < len) {
            size_t take = len - off < step ? len - off : step;
            certone_sha256_update(&ctx, msg + off, take);
            off += take;
            step = step % 67 + 13;
        }
        certone_sha256_final(&ctx, inc);
        if (memcmp(one, inc, sizeof one) != 0) {
            fprintf(stderr, "  mismatch at length %zu\n", len);
        }
        CHECK(memcmp(one, inc, sizeof one) == 0);
    }
}

static void test_input_digest(void)
{
    char out[CERTONE_INPUT_DIGEST_SIZE];
    char file_out[CERTONE_INPUT_DIGEST_SIZE];
    char path[] = "certone_sha256_test.bin";
    FILE *f;

    certone_input_digest("abc", 3, out);
    CHECK_STR(out, "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(strlen(out) == CERTONE_INPUT_DIGEST_SIZE - 1);

    f = fopen(path, "wb");
    CHECK(f != NULL);
    if (f != NULL) {
        int i;
        for (i = 0; i < 20000; i++) { /* spans several read chunks */
            fputs("abc", f);
        }
        fclose(f);
        CHECK_ST(certone_input_digest_file(path, file_out), CERTONE_OK);
        {
            char *buf = (char *)malloc(60000);
            CHECK(buf != NULL);
            if (buf != NULL) {
                for (i = 0; i < 20000; i++) {
                    memcpy(buf + 3 * i, "abc", 3);
                }
                certone_input_digest(buf, 60000, out);
                CHECK_STR(file_out, out);
                free(buf);
            }
        }
        remove(path);
    }
    CHECK_ST(certone_input_digest_file("/nonexistent/certone/snapshot.tar.gz", file_out),
             CERTONE_E_IO);
    CHECK_ST(certone_input_digest_file(NULL, file_out), CERTONE_E_INVALID_ARG);
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        g_fixtures_dir = argv[1];
    }
    RUN(test_known_vectors);
    RUN(test_million_a);
    RUN(test_incremental_matches_one_shot);
    RUN(test_input_digest);
    return test_summary("test_sha256");
}
