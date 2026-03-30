#include "encryption.h" 

int pkcs5_keyed_hash(const char *master,
                     int  master_size,
                     unsigned char *key,
                     unsigned char *salt,
                     int salt_size,
                     const EVP_MD *digest,
                     int key_size,
                     uint32_t iters) {
  ERROR_CHECK_NULL_LOG(master,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(digest,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
  (PKCS5_PBKDF2_HMAC(master, 
                     master_size,
                     salt,
                     salt_size ,
                     iters,
                     digest,
                     key_size,
                     key)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "the hash function failed");
  
  return ERROR_SUCCESS;
} 

int hash_not_keyed(const unsigned char *plain,
                  size_t plain_size,
                  const EVP_MD *type 
                  ,unsigned char *hash
                  ,unsigned int *hash_size){
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hash_size,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  EVP_MD_CTX *ctx = EVP_MD_CTX_new(); 
  ERROR_CHECK_NULL_LOG(ctx,ERROR_LIBSSL_FAILURE,"context initialization failed");

  ERROR_CHECK_SUCCESS_LOG(
    
  (EVP_DigestInit_ex(
    ctx,
    type,
    NULL)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "digest init failed");
  
  ERROR_CHECK_SUCCESS_LOG(
  (EVP_DigestUpdate(ctx,
                    plain,
                    plain_size)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "digest update failed");

  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (EVP_DigestFinal_ex(ctx,
                      hash,
                      hash_size)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "digest final failed",
    failure);
  EVP_MD_CTX_free(ctx);
  return ERROR_SUCCESS;
failure:
  EVP_MD_CTX_free(ctx);
  return ERROR_LIBSSL_FAILURE;

}


/*cipher buffer MUST be larger then the plain buffer with at least 
 * encryption block size difference*/
int encrypt(const EVP_CIPHER *type,
            const unsigned char*key,
            const unsigned char *iv,
            const unsigned char *plain,
            int plain_size,
            unsigned char *cipher,
            int *cipher_size
            ){
  ERROR_CHECK_NULL_LOG(type,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher_size,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ERROR_CHECK_NULL_LOG(ctx,ERROR_NULL_VALUE_GIVEN,"cannot get context");

  int block_size = EVP_CIPHER_block_size(type);
  int cipher_size_tmp = 0;
  *cipher_size = 0;

  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (EVP_EncryptInit_ex(ctx,
                      type,
                      NULL,
                      key,
                      iv)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "encrypt init failed",
    failure);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (EVP_EncryptUpdate(ctx,
                     cipher,
                     &cipher_size_tmp,
                     plain,
                     plain_size)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "encrypt update failed",
    failure);
  *cipher_size += cipher_size_tmp;

  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (EVP_EncryptFinal_ex(ctx,
                     cipher+*cipher_size,
                     &cipher_size_tmp)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "encrypt final failed",
    failure);
  *cipher_size += cipher_size_tmp;


  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (plain_size < ((*cipher_size)+block_size)),
    1,
    ERROR_BUF_OVERFLOW,
    "cipher buffer overflowed",
    overflow);

  EVP_CIPHER_CTX_free(ctx);
  return ERROR_SUCCESS;
failure:
  EVP_CIPHER_CTX_free(ctx);
  return  ERROR_LIBSSL_FAILURE;

overflow:
  EVP_CIPHER_CTX_free(ctx);
  return  ERROR_BUF_OVERFLOW;

}
// EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
//                              const char *properties);
//
// int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
// int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
//                       int *outl, const unsigned char *in, int inl);
// int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
//
//
// int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
// int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
//                       int *outl, const unsigned char *in, int inl);
// int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
//
