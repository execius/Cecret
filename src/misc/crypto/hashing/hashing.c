#include "hashing.h" 

typedef struct HashingField_s {
  ByteBuff_t *text;
  ByteBuff_t *salt;
} HashingField_t ;

int InitHashingField(HashingField_t **hf,
    const ByteBuff_t *text,
    const ByteBuff_t *salt) {
  ERROR_CHECK_NULL_LOG(hf,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(text,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  int rc = 0;

  MALLOC_CHECK_NULL_LOG(*hf,sizeof(HashingField_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate Hashing field");
  (*hf)->text = NULL;
  (*hf)->salt = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*hf)->text,text)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate text bytebuffer",
      rc,cleanup);
 
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*hf)->salt,salt)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate salt bytebuffer",
      rc,cleanup);
 

  return ERROR_SUCCESS;
cleanup:
  DestroyHashingField(*hf);
  *hf = NULL;
  return rc;
}

int CreateHashingField(HashingField_t **hf,
    const ByteBuff_t *text) {
  ERROR_CHECK_NULL_LOG(hf,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(text,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ByteBuff_t *salt_buf = NULL ;
  unsigned char *salt = NULL;
  int rc = 0 ;
  MALLOC_CHECK_NULL_LOG(salt,SALT_SIZE,ERROR_MEMORY_ALLOCATION,
      "cannot allocate encryption field");

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (RAND_bytes(
                  salt,
                  SALT_SIZE
                 )),
      LIBSSL_SUCCESS,
      ERROR_LIBSSL_FAILURE,
      "failed to generate salt",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&salt_buf,
                    salt,
                    (size_t)SALT_SIZE)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for salt",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG( (InitHashingField(
                           hf
                           ,text
                           ,salt_buf)
       ),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize encryption field",
      rc,
      cleanup);
  return ERROR_SUCCESS;
cleanup:
  if (salt){
    OPENSSL_cleanse(salt,SALT_SIZE);
    free(salt);
  }
  if (salt_buf){
    DestroyByteBuff_Secure(salt_buf);
  }
  return rc;
}
int DupHashingField(HashingField_t **dst,
    const HashingField_t *src) {
  ERROR_CHECK_NULL_LOG(src,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(dst,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  int rc = 0;

  MALLOC_CHECK_NULL_LOG(*dst,sizeof(HashingField_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate encryption field");
  (*dst)->text = NULL;
  (*dst)->salt = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*dst)->text,src->text)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate text bytebuffer",
      rc,cleanup);
 
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*dst)->salt,src->salt)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate salt bytebuffer",
      rc,cleanup);

  return ERROR_SUCCESS;
cleanup:
  DestroyHashingField(*dst);
  *dst = NULL;
  return rc;
}


int DestroyHashingField(HashingField_t *hf){
  ERROR_CHECK_NULL_LOG(hf,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  if (hf->text) DestroyByteBuff_Secure(hf->text);
  if (hf->salt) DestroyByteBuff_Secure(hf->salt);

  OPENSSL_cleanse(hf, sizeof(HashingField_t));
  free(hf);
  return ERROR_SUCCESS;
}


int HashingFieldGetText(const HashingField_t *hf,ByteBuff_t **text){
  ERROR_CHECK_NULL_LOG(hf,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(text,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(text,hf->text)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate text buff");
  return ERROR_SUCCESS;
}

int HashingFieldGetSalt(const HashingField_t *hf,ByteBuff_t **salt){
  ERROR_CHECK_NULL_LOG(hf,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(salt,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(salt,hf->salt)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate salt buff");
  return ERROR_SUCCESS;
}


hash_func_t hashing_options_fetchers[] = {
[SHA_512] = EVP_sha512,
[SHA_384] = EVP_sha384,
[SHA_256] = EVP_sha256
};

int pkcs5_keyed_hash(const char *master,
                     int  master_size,
                     unsigned char *key,
                     const unsigned char *salt,
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

int pkcs5_keyed_hash_bytebuff(
    const ByteBuff_t *master,
    ByteBuff_t **key,
    size_t key_size,
    const ByteBuff_t *salt,
    const EVP_MD *digest,
    uint32_t iters)
{
  ERROR_CHECK_NULL_LOG(master,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(digest,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  unsigned char *master_str = NULL;
  unsigned char *salt_str = NULL;
  unsigned char *key_str = NULL;
  int master_size = 0;
  int salt_size = 0;
  int rc = 0;

  MALLOC_CHECK_NULL_LOG(key_str,
      key_size,
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate for key_str");
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (
       GetLenByteBuff(master
         ,(size_t *) &master_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get master size from bytebuffer struct",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (
       GetLenByteBuff(salt
         ,(size_t *) &salt_size)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get salt size from bytebuffer struct",
      rc,cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (
       GetBuffByteBuff(salt
                       ,(unsigned char **) &salt_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get salt buffer from bytebuffer struct",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (
       GetBuffByteBuff(master
                       ,&master_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get master buffer from bytebuffer struct",
      rc,cleanup);


  ERROR_CHECK_SUCCESS_LOG(
  (PKCS5_PBKDF2_HMAC((char *)master_str, 
                     master_size,
                     salt_str,
                     salt_size ,
                     iters,
                     digest,
                     key_size,
                     key_str)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "the hash function failed");
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(key,
                    key_str,
                    key_size)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for hash",
      rc,cleanup);
  rc =  ERROR_SUCCESS;
  goto cleanup;

cleanup:

  if (master_str){ 
    OPENSSL_cleanse(master_str,master_size);
    free(master_str);
  }

  if (salt_str){ 
    OPENSSL_cleanse(salt_str,salt_size);
    free(salt_str);
  }

  if (key_str){ 
    OPENSSL_cleanse(key_str,key_size);
    free(key_str);
  }
  return rc;

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

  int rc = 0;
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

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (EVP_DigestFinal_ex(ctx,
                      hash,
                      hash_size)),

    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "digest final failed",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  EVP_MD_CTX_free(ctx);
  return rc;

}


int pkcs5_keyed_hash_HashingField(
    const HashingField_t *master,
    HashingField_t **key,
    int key_size,
    const EVP_MD *digest,
    uint32_t iters)
{
  ERROR_CHECK_NULL_LOG(master,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(digest,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ByteBuff_t *key_bb = NULL;
  int rc = 0;


  ERROR_CHECK_SUCCESS_LOG(
  (pkcs5_keyed_hash_bytebuff(
                             master->text
                             ,&key_bb
                             ,key_size
                             ,master->salt
                             ,digest
                             ,iters)
   ),

    LIBSSL_SUCCESS,
    ERROR_HASHBYTEBUFF_FAILED,
    "hasing byte buffer failed");
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitHashingField(key,
                    key_bb,
                    master->salt)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to initialize hashing field ",
      rc,cleanup);
  rc =  ERROR_SUCCESS;
  goto cleanup;

cleanup:
  if (key_bb){ 
    DestroyByteBuff_Secure(key_bb);
  }
  return rc;

} 
