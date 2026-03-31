#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "includes.h"
#include "bytebuffer.h" 

typedef const EVP_CIPHER* (*cipher_func_t)(void);
typedef const EVP_MD* (*hash_func_t)(void);
int pkcs5_keyed_hash(const char *master,
                     int  master_size,
                     unsigned char *key,
                     unsigned char *salt,
                     int salt_size,
                     const EVP_MD *digest,
                     int key_size,
                     uint32_t iters) ;
int hash_not_keyed(const unsigned char *plain,
                  size_t plain_size,
                  const EVP_MD *type 
                  ,unsigned char *hash
                  ,unsigned int *hash_size);

typedef enum { 
  AES_256_CTR,
  AES_192_CTR,
  AES_128_CTR,
  CHACHA20,
  CAMELLIA_256_CTR,
  CAMELLIA_192_CTR,
  CAMELLIA_128_CTR
} Encryption_options_idx;

typedef enum { 
  SHA_512,
  SHA_384,
  SHA_256
} hashing_options_idx;
enum CryptoErrors{
  ERROR_HASH_FAILED = -5000,

};

extern cipher_func_t encryption_options_fetchers[];
extern hash_func_t hashing_options_fetchers[];
#endif /* ifndef ENRYPTION_H */
