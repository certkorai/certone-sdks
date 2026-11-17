/*
 * Internal helpers shared by the CertOne C SDK sources and its offline unit tests.
 * Not part of the public API: names and signatures may change between releases.
 */
#ifndef CERTONE_INTERNAL_H
#define CERTONE_INTERNAL_H

#include "certone.h"

#include <stddef.h>

/* Growable byte buffer, always kept NUL-terminated when data != NULL. limit == 0 means none. */
typedef struct certone_buf {
    char *data;
    size_t len;
    size_t cap;
    size_t limit;
    int overflow; /* set when an append would exceed limit */
    int nomem;    /* set when an allocation failed        */
} certone_buf;

void certone__buf_free(certone_buf *b);
certone_status certone__buf_append(certone_buf *b, const void *data, size_t len);
certone_status certone__buf_append_str(certone_buf *b, const char *s);
/* Append s as a quoted JSON string. CERTONE_E_INVALID_ARG if s is not valid UTF-8. */
certone_status certone__buf_append_json_string(certone_buf *b, const char *s);

/* 1 if s[0..len) is well-formed UTF-8 (RFC 3629: no overlongs, no surrogates, <= U+10FFFF). */
int certone__utf8_valid(const char *s, size_t len);

/* Percent-encode one URL path segment (RFC 3986 unreserved characters are kept). */
certone_status certone__percent_encode(const char *segment, char **out);

/* Build the POST /v1/checks/report JSON body. */
certone_status certone__build_ingest_body(const char *report_json,
                                          const certone_ingest_options *options, char **out);

/* Collect the non-NULL scan options as multipart form fields, in a fixed order.
 * Writes up to 8 (name, value) pairs and returns how many. tee is only included when
 * include_tee is non-zero (submit_process). */
size_t certone__scan_fields(const certone_scan_options *options, int include_tee,
                            const char *names[8], const char *values[8]);

/* Human-readable `detail` for an HTTP error body: the API's "detail" string, the raw JSON of a
 * non-string detail (e.g. validation errors), or the body text. Control characters become
 * spaces; the result is truncated on a UTF-8 boundary to fit out (always NUL-terminated). */
void certone__error_detail(const char *body, size_t body_len, char *out, size_t out_size);

#endif /* CERTONE_INTERNAL_H */
