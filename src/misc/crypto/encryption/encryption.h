#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "includes.h"

typedef struct EncryptionField_s EncryptionField_t ;

typedef struct HashingField_s HashingField_t ;

typedef const EVP_CIPHER* (*cipher_func_t)(void);

typedef const EVP_MD* (*hash_func_t)(void);

typedef enum { 
  AES_256_GCM,
  AES_192_GCM,
  AES_128_GCM,
  CHACHA20_POLY1305,
} Encryption_options_idx;



#include "user.h"
#include "usersconfig.h"
#include "bytebuffer.h"

/*this deals with setting the txt and 
 * generating the IV , the tag is made at encryption*/
int CreateEncryptionField(
    const EVP_CIPHER *type,
    EncryptionField_t **ef,
    const ByteBuff_t *text);


/*only copies tag if it's not null*/
int DupEncryptionField(EncryptionField_t **dst,
    const EncryptionField_t *src);

int DestroyEncryptionField(EncryptionField_t *ef);

int EncryptionFieldGetText(const EncryptionField_t *ef,ByteBuff_t **text);
int EncryptionFieldGetIv(const EncryptionField_t *ef,ByteBuff_t **iv);

/*errors out if tag is NULL*/
int EncryptionFieldGetTag(const EncryptionField_t *ef,ByteBuff_t **tag);


/*cipher buffer MUST be larger then the plain buffer with at least 
 * encryption block size difference
 *
 * @tag size MUST be equal  to the global TAG_SIZE to avoid overflow  
 *
 * also this is STRICTLY AEAD GCM and chacha-poly1305 encryptions , for integrity*/
int encrypt(const EVP_CIPHER *type,
            const unsigned char*key,
            const unsigned char *iv,
            const unsigned char *plain,
            int plain_size,
            unsigned char *cipher,
            int *cipher_size,
            unsigned char *tag);

int EncryptByteBuff(
            const EVP_CIPHER *type,
            const ByteBuff_t *plain,
            const ByteBuff_t *key,
            const ByteBuff_t *iv,
            ByteBuff_t **cipher,
            ByteBuff_t **tag);

int decrypt(const EVP_CIPHER *type,
            const unsigned char*key,
            const unsigned char *iv,
            const unsigned char *cipher,
            int cipher_size,
            unsigned char *plain,
            int *plain_size,
            unsigned char *tag);
int DecryptByteBuff(
            const EVP_CIPHER *type,
            const ByteBuff_t *cipher,
            const ByteBuff_t *key,
            const ByteBuff_t *iv,
            ByteBuff_t **plain,
            ByteBuff_t *tag);
int DecryptEncryptionField(
    const EVP_CIPHER *type,
    const EncryptionField_t *cipher,
    const ByteBuff_t *key,
    EncryptionField_t **plain);

int EncryptEncryptionField(
    const EVP_CIPHER *type,
    const EncryptionField_t *plain,
    const ByteBuff_t *key,
    EncryptionField_t **cipher);

enum CryptoencErrors{
  ERROR_ENCRYPTION_FAILURE = -5001,
  ERROR_ENCRYPTBYTEBUFF_FAILURE = -5002,
  ERROR_DECRYPTION_FAILURE = -5003,
  ERROR_DECRYPTBYTEBUFF_FAILURE = -5004,

  ERROR_INITENCRYPTIONFIELD_FAILURE = -5005,
  ERROR_DUPENCRYPTIONFIELD_FAILURE = -5006,
  ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE = -5007,
  ERROR_CREATEENCRYPTIONFIELD_FAILURE = -5008,
  ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE = -5009

};
extern cipher_func_t encryption_options_fetchers[];
extern hash_func_t hashing_options_fetchers[];
#endif /* ifndef ENRYPTION_H */
