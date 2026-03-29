#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "includes.h"

typedef struct EncryptionOption_s {
  const EVP_CIPHER *(*EncryptionScheme)(void);
  size_t key_size;
  size_t iv_size;
} EncryptionOption_t ;

typedef struct HashOption_s {
  const EVP_MD *(*digest)(void);
  size_t key_size;
  size_t salt_size;
} HashOption_t ;
typedef struct EncryptedBuff_s {
  char cipher[STRMAX];
  size_t cipher_len;
} EncryptedBuff_t ;
#endif
