#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "includes.h"

typedef struct EncryptionOption_s {
  const EVP_CIPHER *(*EncryptionScheme)(void);
  size_t key_size;
  size_t iv_size;
} EncryptionOption_t ;

typedef struct HashOption_s {
  const EVP_MD *digest;
  unsigned int key_size;
  unsigned int salt_size;
} HashOption_t ;
typedef struct EncryptedBuff_s {
  char cipher[STRMAX];
  size_t cipher_len;
} EncryptedBuff_t ;

int pkcs5_keyed_hash(const char *master,
                     size_t master_size,
                     unsigned char *key,
                     unsigned char *salt,
                     size_t salt_size,
                     const EVP_MD *digest,
                     size_t key_size,
                     uint32_t iters) ;
int hash_not_keyed(const unsigned char *plain,
                  size_t plain_size,
                  const EVP_MD *type 
                  ,unsigned char *hash
                  ,unsigned int *hash_size);


#endif
