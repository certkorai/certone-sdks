# Plain Makefile for the CertOne C SDK (CMake is the primary build; this needs only make + cc).
#
#   make                       # build/libcertone.a, build/libcertone.so, tests, quickstart
#   make check                 # run the offline unit tests
#   make CC=aarch64-linux-gnu-gcc BUILD=build-arm64 PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
#   make install PREFIX=/usr/local
#
# libcurl flags come from pkg-config (override CURL_CFLAGS / CURL_LIBS when cross-compiling
# without a pkg-config for the target).

CC ?= cc
AR ?= ar
PKG_CONFIG ?= pkg-config
BUILD ?= build
PREFIX ?= /usr/local
FIXTURES ?= ../conformance/fixtures

CURL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libcurl)
CURL_LIBS ?= $(shell $(PKG_CONFIG) --libs libcurl)

WARNINGS = -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wconversion -Wno-sign-conversion
CFLAGS ?= -O2 -g
ALL_CFLAGS = -std=c11 $(WARNINGS) $(CFLAGS) -Iinclude -Isrc $(CURL_CFLAGS)

SRCS = src/certone.c src/json.c src/sha256.c
OBJS = $(SRCS:src/%.c=$(BUILD)/obj/%.o)
PIC_OBJS = $(SRCS:src/%.c=$(BUILD)/pic/%.o)
TESTS = json sha256 request client
TEST_BINS = $(TESTS:%=$(BUILD)/test_%)

.PHONY: all lib check clean install
all: lib $(TEST_BINS) $(BUILD)/quickstart
lib: $(BUILD)/libcertone.a $(BUILD)/libcertone.so

$(BUILD)/obj/%.o: src/%.c include/certone.h src/internal.h
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(BUILD)/pic/%.o: src/%.c include/certone.h src/internal.h
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -fPIC -fvisibility=hidden -DCERTONE_SHARED -c $< -o $@

$(BUILD)/libcertone.a: $(OBJS)
	$(AR) rcs $@ $^

$(BUILD)/libcertone.so: $(PIC_OBJS)
	$(CC) -shared -Wl,-soname,libcertone.so.0 -o $@ $^ $(LDFLAGS) $(CURL_LIBS)

$(BUILD)/test_%: tests/test_%.c tests/test_util.h $(BUILD)/libcertone.a
	$(CC) $(ALL_CFLAGS) -Itests $< -o $@ $(BUILD)/libcertone.a $(LDFLAGS) $(CURL_LIBS) -lpthread

$(BUILD)/quickstart: examples/quickstart.c $(BUILD)/libcertone.a
	$(CC) $(ALL_CFLAGS) $< -o $@ $(BUILD)/libcertone.a $(LDFLAGS) $(CURL_LIBS)

check: $(TEST_BINS)
	@set -e; for t in $(TESTS); do (cd $(BUILD) && $(TEST_RUNNER) ./test_$$t $(abspath $(FIXTURES))); done

install: lib
	install -d $(DESTDIR)$(PREFIX)/include $(DESTDIR)$(PREFIX)/lib
	install -m 644 include/certone.h $(DESTDIR)$(PREFIX)/include/
	install -m 644 $(BUILD)/libcertone.a $(DESTDIR)$(PREFIX)/lib/
	install -m 755 $(BUILD)/libcertone.so $(DESTDIR)$(PREFIX)/lib/libcertone.so.0
	ln -sf libcertone.so.0 $(DESTDIR)$(PREFIX)/lib/libcertone.so

clean:
	rm -rf $(BUILD)
