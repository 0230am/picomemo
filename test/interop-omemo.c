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
#include "o/store.inc"

#define BUNDLE_SIZE (4 + 4 + 4 + 33 + 33 + 64 + 33)

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

static uint32_t ReadU32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
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

static void Initial(const char *bundle_path, const char *message_path,
                    const char *session_path, const char *sign_path) {
  uint8_t bundle[BUNDLE_SIZE];
  assert(ReadFile(bundle_path, bundle, sizeof(bundle)) == sizeof(bundle));
  assert(!memcmp(bundle, "OMB0", 4));

  uint32_t spk_id = ReadU32(bundle + 4);
  uint32_t pk_id = ReadU32(bundle + 8);
  omemoSerializedKey ik, spk, pk;
  omemoCurveSignature spks;
  memcpy(ik, bundle + 12, sizeof(ik));
  memcpy(spk, bundle + 45, sizeof(spk));
  memcpy(spks, bundle + 78, sizeof(spks));
  memcpy(pk, bundle + 142, sizeof(pk));

  struct omemoStore store;
  assert(!omemoSetupStore(&store));
  struct omemoSession session = {0};
  assert(!omemoInitiateSession(&session, &store, spks, spk, ik, pk,
                               spk_id, pk_id));

  uint8_t plaintext[OMEMO_KEYSIZE];
  memset(plaintext, 0x77, 16);
  memset(plaintext + 16, 0x88, 16);
  struct omemoKeyMessage message = {0};
  assert(!omemoEncryptKey(&session, &message, plaintext,
                          sizeof(plaintext)));
  assert(message.isprekey);
  WriteFile(message_path, message.p, message.n);
  SaveSession(session_path, &session);

  uint8_t sign = !!(store.cursignedprekey.sig[63] & 0x80);
  WriteFile(sign_path, &sign, sizeof(sign));
}

static void Passive(const char *message_path, const char *response_path) {
  uint8_t message[1000], plaintext[OMEMO_KEYSIZE];
  size_t messagen = ReadFile(message_path, message, sizeof(message));
  struct omemoStore store;
  assert(!omemoDeserializeStore(store_inc, store_inc_len, &store));
  struct omemoSession session = {0};

  uint8_t expected[OMEMO_KEYSIZE];
  memset(expected, 0x55, 16);
  memset(expected + 16, 0xaa, 16);
  size_t plaintextn = sizeof(plaintext);
  assert(!omemoDecryptKey(&session, &store, plaintext, &plaintextn,
                          true, message, messagen));
  assert(plaintextn == sizeof(expected));
  assert(!memcmp(expected, plaintext, sizeof(expected)));

  memset(plaintext, 0xcc, 16);
  memset(plaintext + 16, 0x33, 16);
  struct omemoKeyMessage response = {0};
  assert(!omemoEncryptKey(&session, &response, plaintext,
                          sizeof(plaintext)));
  assert(!response.isprekey);
  WriteFile(response_path, response.p, response.n);
}

static void Next(const char *message_path, const char *response_path,
                 const char *session_path) {
  uint8_t serialized[1000], message[1000];
  size_t serializedn = ReadFile(session_path, serialized,
                                sizeof(serialized));
  size_t messagen = ReadFile(message_path, message, sizeof(message));
  struct omemoSession session = {0};
  assert(!omemoDeserializeSession(serialized, serializedn, &session));

  uint8_t plaintext[OMEMO_KEYSIZE], expected[OMEMO_KEYSIZE];
  memset(expected, 0x99, 16);
  memset(expected + 16, 0xaa, 16);
  size_t plaintextn = sizeof(plaintext);
  struct omemoStore store = {.init = true};
  memcpy(store.identity.pub, session.identity, sizeof(session.identity));
  assert(!omemoDecryptKey(&session, &store, plaintext, &plaintextn,
                          false, message, messagen));
  assert(plaintextn == sizeof(expected));
  assert(!memcmp(expected, plaintext, sizeof(expected)));

  memset(plaintext, 0xcc, 16);
  memset(plaintext + 16, 0x33, 16);
  struct omemoKeyMessage response = {0};
  assert(!omemoEncryptKey(&session, &response, plaintext,
                          sizeof(plaintext)));
  assert(!response.isprekey);
  WriteFile(response_path, response.p, response.n);
  SaveSession(session_path, &session);
}

int main(int argc, char **argv) {
  assert(argc == 6);
  srand(!strcmp(argv[1], "initial") ? 1 : 2);
  omemoSetCallbacks(NULL, NULL, Random);
  if (!strcmp(argv[1], "initial"))
    Initial(argv[2], argv[3], argv[4], argv[5]);
  else if (!strcmp(argv[1], "passive"))
    Passive(argv[2], argv[3]);
  else {
    assert(!strcmp(argv[1], "next"));
    Next(argv[2], argv[3], argv[4]);
  }
  return 0;
}
