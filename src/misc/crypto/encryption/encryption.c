#include "encryption.h" 


cipher_func_t encryption_options_fetchers[] = {
[AES_256_CTR] = EVP_aes_256_ctr,
[AES_192_CTR] = EVP_aes_192_ctr,
[AES_128_CTR] = EVP_aes_128_ctr,
[CHACHA20]    = EVP_chacha20,
[CAMELLIA_256_CTR] = EVP_camellia_256_ctr,
[CAMELLIA_192_CTR] = EVP_camellia_192_ctr,
[CAMELLIA_128_CTR] = EVP_camellia_128_ctr
};

hash_func_t hashing_options_fetchers[] = {
[SHA_512] = EVP_sha512,
[SHA_384] = EVP_sha384,
[SHA_256] = EVP_sha256
};

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
int EncryptByteBuff(
            const ByteBuff_t *plain,
            const ByteBuff_t *iv,
            ByteBuff_t **cipher,
            user_t *user)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(plain,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  unsigned char *key_str = NULL;
  unsigned char *iv_str = NULL;
  unsigned char *plain_str = NULL;
  unsigned char *cipher_str = NULL;
  UserConfig_t *userconfig = NULL;
  int plain_size = 0;
  int cipher_size = 0;
  int cipher_max = 0;
  int rc = 0;
  ByteBuff_t *key = NULL;
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (UserGetUserConf(user
                       ,&userconfig)
      ),
      ERROR_SUCCESS,
      ERROR_GETUSRCONF_FAILURE,
      "failed to get userconfig from user",
      failure_getusrconf);
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (GetLenByteBuff(plain
                       ,(size_t *)&plain_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get plain len from byte buff",
      failure_getlenbytebuff);

  /*+512 just in case*/
  cipher_max = plain_size +EVP_CIPHER_get_block_size(
      encryption_options_fetchers[userconfig->encryption_option_idx]())+512;
  MALLOC_CHECK_NULL_LOG(cipher,
      cipher_max,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for cipher str");


  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (UserGetKey(user,
                       &key)), 
      ERROR_SUCCESS,
      ERROR_USER_GET_KEY,
      "error gettingn key from user ",
      failure_usrgetkey);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (GetBuffByteBuff(key
                       ,(unsigned char **)&key_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get key  str from byte buff",
      failure_getbuffbytebuff);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (GetBuffByteBuff(iv
                       ,(unsigned char **)&iv_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get iv  str from byte buff",
      failure_getbuffbytebuff);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (GetBuffByteBuff(plain
                       ,(unsigned char **)&plain_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get plain  str from byte buff",
      failure_getbuffbytebuff);



  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (encrypt(encryption_options_fetchers[userconfig->encryption_option_idx]()
               ,key_str
               ,iv_str
               ,plain_str
               ,plain_size
               ,cipher_str
               ,&cipher_size
      )),
      ERROR_SUCCESS,
      ERROR_ENCRYPTION_FAILURE,
      "failed to encrypt",
      failure_encryption);


  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (InitByteBuff(cipher
                    ,cipher_str
                    ,(size_t)cipher_size)
      ),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to get plain  str from byte buff",
      failure_initbuff);

  rc = ERROR_SUCCESS;
cleanup:
  if (cipher_str) {
    OPENSSL_cleanse(cipher_str,strlen((const char *)cipher_str));
    free(cipher_str);
    }
  if (plain_str) {
    OPENSSL_cleanse(plain_str,strlen((const char *)plain_str));
    free(plain_str);
    }
  if (iv_str) {
    OPENSSL_cleanse(iv_str,strlen((const char *)iv_str));
    free(iv_str);
    }
  if (userconfig) {
    OPENSSL_cleanse(userconfig,sizeof(UserConfig_t));
    free(userconfig);
    }
  return rc;

failure_initbuff:
  rc = ERROR_BUFFINIT_FAILURE;
  goto cleanup;
failure_usrgetkey:
  rc = ERROR_USER_GET_KEY;
  goto cleanup;
failure_encryption:
  rc = ERROR_ENCRYPTION_FAILURE;
  goto cleanup;
failure_getbuffbytebuff:
  rc = ERROR_GETBUFF_FAILURE;
  goto cleanup;
failure_getlenbytebuff:
  rc = ERROR_GETLEN_FAILURE;
  goto cleanup;
failure_getusrconf:
  rc = ERROR_GETUSRCONF_FAILURE;
  goto cleanup;

}

