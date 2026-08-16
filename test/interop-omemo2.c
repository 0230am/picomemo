/**
 * Copyright 2024 mierenhoop
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "omemo.h"
#include "o/store2.inc"

static int Random(void *d, size_t n) {
  for (size_t i = 0; i < n; i++)
    ((uint8_t *)d)[i] = rand();
  return 0;
}

static size_t ReadFile(const char *path, uint8_t *buf, size_t n) {
  FILE *f = fopen(path, "rb");
  assert(f);
  size_t readn = fread(buf, 1, n, f);
  assert(readn > 0 && !ferror(f));
  assert(fgetc(f) == EOF);
  fclose(f);
  return readn;
}

static void WriteFile(const char *path, const uint8_t *buf, size_t n) {
  FILE *f = fopen(path, "wb");
  assert(f);
  assert(fwrite(buf, 1, n, f) == n);
  assert(!fclose(f));
}

static void SaveSession(const char *path,
                        const struct omemoSession *session) {
  size_t n = omemoGetSerializedSessionSize(session);
  uint8_t *buf = malloc(n);
  assert(buf);
  omemoSerializeSession(buf, session);
  WriteFile(path, buf, n);
  free(buf);
}

int main(int argc, char **argv) {
  assert(argc == 5);
  srand(!strcmp(argv[1], "initial") ? 1 : 2);
  omemoSetCallbacks(NULL, NULL, Random);

  struct omemoStore store;
  assert(!omemoDeserializeStore(store_inc, store_inc_len, &store));
  struct omemoSession session = {0};
  uint8_t input[1000];
  size_t inputn = ReadFile(argv[2], input, sizeof(input));

  uint8_t expected[OMEMO_KEYSIZE], plaintext[OMEMO_KEYSIZE];
  size_t plaintextn = sizeof(plaintext);
  if (!strcmp(argv[1], "initial")) {
    memset(expected, 0x55, 32);
    memset(expected + 32, 0xaa, 16);
    assert(!omemoDecryptKey(&session, &store, plaintext, &plaintextn,
                            true, input, inputn));
    assert(plaintextn == sizeof(expected));
    assert(!memcmp(expected, plaintext, sizeof(expected)));
    memset(plaintext, 0xcc, 32);
    memset(plaintext + 32, 0x33, 16);
  } else {
    assert(!strcmp(argv[1], "next"));
    uint8_t serialized[1000];
    size_t serializedn = ReadFile(argv[4], serialized,
                                  sizeof(serialized));
    assert(!omemoDeserializeSession(serialized, serializedn, &session));
    memset(expected, 0xdd, 32);
    memset(expected + 32, 0x44, 16);
    assert(!omemoDecryptKey(&session, &store, plaintext, &plaintextn,
                            false, input, inputn));
    assert(plaintextn == sizeof(expected));
    assert(!memcmp(expected, plaintext, sizeof(expected)));
    memset(plaintext, 0xee, 32);
    memset(plaintext + 32, 0x66, 16);
  }
  struct omemoKeyMessage response = {0};
  assert(!omemoEncryptKey(&session, &response, plaintext,
                          sizeof(plaintext)));
  assert(!response.isprekey);
  WriteFile(argv[3], response.p, response.n);
  SaveSession(argv[4], &session);
  return 0;
}
