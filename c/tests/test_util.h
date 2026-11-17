/* Minimal self-contained test harness for the CertOne C SDK unit tests (no dependencies). */
#ifndef CERTONE_TEST_UTIL_H
#define CERTONE_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks;
static int g_failures;
static int g_tests;
static const char *g_fixtures_dir = ".";

#define CHECK(cond)                                                                            \
    do {                                                                                       \
        g_checks++;                                                                            \
        if (!(cond)) {                                                                         \
            g_failures++;                                                                      \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                                      \
    } while (0)

#define CHECK_ST(expr, expected)                                                               \
    do {                                                                                       \
        int got_ = (int)(expr);                                                                \
        g_checks++;                                                                            \
        if (got_ != (int)(expected)) {                                                         \
            g_failures++;                                                                      \
            fprintf(stderr, "%s:%d: %s returned %d, expected %s (%d)\n", __FILE__, __LINE__,   \
                    #expr, got_, #expected, (int)(expected));                                  \
        }                                                                                      \
    } while (0)

#define CHECK_STR(actual, expected)                                                            \
    do {                                                                                       \
        const char *a_ = (actual);                                                             \
        const char *e_ = (expected);                                                           \
        g_checks++;                                                                            \
        if (a_ == NULL || strcmp(a_, e_) != 0) {                                               \
            g_failures++;                                                                      \
            fprintf(stderr, "%s:%d: %s == \"%s\", expected \"%s\"\n", __FILE__, __LINE__,      \
                    #actual, a_ != NULL ? a_ : "(null)", e_);                                  \
        }                                                                                      \
    } while (0)

#define CHECK_CONTAINS(haystack, needle)                                                       \
    do {                                                                                       \
        const char *h_ = (haystack);                                                           \
        g_checks++;                                                                            \
        if (h_ == NULL || strstr(h_, (needle)) == NULL) {                                      \
            g_failures++;                                                                      \
            fprintf(stderr, "%s:%d: %s does not contain \"%s\"\n", __FILE__, __LINE__,       \
                    #haystack, (needle));                                                      \
        }                                                                                      \
    } while (0)

#define CHECK_PREFIX(actual, prefix)                                                           \
    do {                                                                                       \
        const char *p_ = (actual);                                                             \
        g_checks++;                                                                            \
        if (p_ == NULL || strncmp(p_, (prefix), strlen(prefix)) != 0) {                        \
            g_failures++;                                                                      \
            fprintf(stderr, "%s:%d: %s starts with \"%.80s\", expected \"%s\"\n", __FILE__,     \
                    __LINE__, #actual, p_ != NULL ? p_ : "(null)", (prefix));                  \
        }                                                                                      \
    } while (0)

#define RUN(test)                                                                              \
    do {                                                                                       \
        int before_ = g_failures;                                                              \
        g_tests++;                                                                             \
        test();                                                                                \
        printf("  %-48s %s\n", #test, g_failures == before_ ? "ok" : "FAILED");                \
    } while (0)

static inline int test_summary(const char *suite)
{
    printf("%s: %d tests, %d checks, %d failed\n", suite, g_tests, g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

/* Read <g_fixtures_dir>/<name> into a NUL-terminated heap buffer (NULL on error). */
static inline char *read_fixture(const char *name)
{
    char path[1024];
    FILE *f;
    char *data = NULL;
    size_t len = 0;
    size_t cap = 0;
    size_t n;
    char chunk[4096];

    snprintf(path, sizeof path, "%s/%s", g_fixtures_dir, name);
    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "cannot open fixture %s\n", path);
        return NULL;
    }
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) {
        if (len + n + 1 > cap) {
            size_t ncap = (len + n + 1) * 2;
            char *grown = (char *)realloc(data, ncap);
            if (grown == NULL) {
                free(data);
                fclose(f);
                return NULL;
            }
            data = grown;
            cap = ncap;
        }
        memcpy(data + len, chunk, n);
        len += n;
    }
    fclose(f);
    if (data == NULL) {
        data = (char *)calloc(1, 1);
    } else {
        data[len] = '\0';
    }
    return data;
}

#endif /* CERTONE_TEST_UTIL_H */
