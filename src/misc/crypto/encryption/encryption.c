#include "encryption.h" 

int pkcs5_keyed_hash(const char *master,
                     size_t master_size,
                     unsigned char *key,
                     unsigned char *salt,
                     size_t salt_size,
                     const EVP_MD *digest,
                     size_t key_size,
                     uint32_t iters) {
  ERROR_CHECK_NULL_LOG(master,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(digest,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
    (PKCS5_PBKDF2_HMAC(
      master, 
      master_size,
      salt,
      salt_size ,
      iters,
      digest,
      key_size,
      key))
    ,
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
    (EVP_DigestUpdate(
      ctx,
      plain,
      plain_size)),
    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "digest update failed");

  ERROR_CHECK_SUCCESS_LOG(
    (EVP_DigestFinal_ex(
      ctx,
      hash,
      hash_size)),
    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "digest final failed");
  EVP_MD_CTX_free(ctx);
  return ERROR_SUCCESS;

}
