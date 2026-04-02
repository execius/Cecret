#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "includes.h"

typedef const EVP_CIPHER* (*cipher_func_t)(void);

typedef const EVP_MD* (*hash_func_t)(void);

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


#include "user.h"
#include "usersconfig.h"
#include "bytebuffer.h"

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

/*cipher buffer MUST be larger then the plain buffer with at least 
 * encryption block size difference*/
int encrypt(const EVP_CIPHER *type,
            const unsigned char*key,
            const unsigned char *iv,
            const unsigned char *plain,
            int plain_size,
            unsigned char *cipher,
            int *cipher_size);

int EncryptByteBuff(
            const ByteBuff_t *plain,
            const ByteBuff_t *iv,
            ByteBuff_t **cipher,
            user_t *user);
enum CryptoErrors{
  ERROR_HASH_FAILED = -5000,
  ERROR_ENCRYPTION_FAILURE = -5001,
  ERROR_ENCRYPTBYTEBUFF_FAILURE = -5002

};

extern cipher_func_t encryption_options_fetchers[];
extern hash_func_t hashing_options_fetchers[];
#endif /* ifndef ENRYPTION_H */
