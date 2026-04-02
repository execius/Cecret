#include "user.h"

typedef struct user_s {
  ByteBuff_t *username;
  ByteBuff_t *user_db_path;

  ByteBuff_t *hashed_pass;
  ByteBuff_t *key;
  /*used for lookup*/
  ByteBuff_t *hmac_salt;
  ByteBuff_t *password_salt;
  ByteBuff_t *enc_salt;
  UserConfig_t userconf;
} user_t;

int InitUser(user_t **user
             ,ByteBuff_t *username
             ,ByteBuff_t *hashed_pass
             ,ByteBuff_t *key
             ,ByteBuff_t *hmac_salt
             ,ByteBuff_t *password_salt
             ,ByteBuff_t *enc_salt
             ,ByteBuff_t *user_db_path
             ,UserConfig_t userconfig)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hashed_pass,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hmac_salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password_salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user_db_path,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;
  *user = NULL;
  MALLOC_CHECK_NULL_LOG(*user,sizeof(user_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate user");

  (*user)->hmac_salt = NULL;
  (*user)->user_db_path = NULL;
  (*user)->hashed_pass = NULL;
  (*user)->key = NULL;
  (*user)->password_salt = NULL;
  (*user)->enc_salt = NULL;
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->username,username)), ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username bytebuffer",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->user_db_path,user_db_path)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate user db path bytebuffer",
      rc,cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->hashed_pass,hashed_pass)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate hashed pass bytebuffer",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->password_salt,password_salt)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate password_salt salt buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->hmac_salt,hmac_salt)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate hmac_salt buff",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->key,key)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate key buff",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*user)->enc_salt,enc_salt)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate enc_salt buff",
      rc,cleanup);
  memcpy(&(*user)->userconf,&userconfig,sizeof(UserConfig_t));

  return ERROR_SUCCESS;
cleanup:
  DestroyUser(*user);
  *user = NULL;
  return rc;
}




int CreateUser(user_t **user
    ,ByteBuff_t *username
    ,ByteBuff_t *password
    ,UserConfig_t userconfig)

{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  *user = NULL;
  int rc;
  char *password_str = NULL;
  int password_len = 0;
  unsigned char hmac_salt[SALT_SIZE];
  unsigned char password_salt[SALT_SIZE];
  unsigned char enc_salt[SALT_SIZE];
  unsigned char hashed_pass[STRMAX];
  unsigned char key[STRMAX];
  ByteBuff_t *hmac_salt_buf = NULL,
             *password_salt_buf = NULL,
             *user_db_path = NULL,
             *hashed_pass_buf = NULL,
             *enc_salt_buf = NULL,
             *key_buf = NULL; 


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (RAND_bytes(
      hmac_salt,
      SALT_SIZE)),
    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "failed to generate hmac salt",
    rc,cleanup);



  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (RAND_bytes(
                  password_salt,
                  SALT_SIZE)
      ),
      LIBSSL_SUCCESS,
      ERROR_LIBSSL_FAILURE,
      "failed to generate hmac salt",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (RAND_bytes(
      enc_salt,
      SALT_SIZE)),
    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "failed to generate encryption salt",
    rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (
       GetBuffByteBuff(password
                       ,(unsigned char **) &password_str)
      ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_FAILURE,
      "failed to get password buffer from bytebuffer struct",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (
       GetLenByteBuff(password
                       ,(size_t *) &password_len)
      ),
      ERROR_SUCCESS,
      ERROR_GETLEN_FAILURE,
      "failed to get password lenght from bytebuffer struct",
      rc,cleanup);

  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (pkcs5_keyed_hash(
      password_str,
      password_len,
      hashed_pass,
      password_salt,
      SALT_SIZE,
      hashing_options_fetchers[userconfig.hashing_option_idx](),
      EVP_MD_size(hashing_options_fetchers[userconfig.hashing_option_idx]()),
      globalconf->password_hashing_iters)),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash password",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (pkcs5_keyed_hash(
      password_str,
      password_len,
      key,
      enc_salt,
      SALT_SIZE,
      hashing_options_fetchers[userconfig.key_hashing_option_idx](),
      EVP_MD_size(hashing_options_fetchers[userconfig.key_hashing_option_idx]()),
      globalconf->key_derivation_iters)),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to derive encryption key",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&user_db_path,
                    (unsigned char *)"",
                    0)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for user db path",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendByteBuff(user_db_path,
                    globalconf->master_db_dir_path)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to append byte buff while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"/")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"users")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append 'users' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,"/")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/' while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendByteBuff(user_db_path,
                    username)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to append byte buff while building user db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(user_db_path,".db")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append 'users' while building user db path",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&hashed_pass_buf,
                    hashed_pass,
                    EVP_MD_size(
                      hashing_options_fetchers[userconfig.hashing_option_idx]()))),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for hashed pass",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&key_buf,
                    key,
                    EVP_MD_size(
                      hashing_options_fetchers[userconfig.key_hashing_option_idx]()))),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for key",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&hmac_salt_buf,
                    hmac_salt,
                    SALT_SIZE)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for hmac salt",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&password_salt_buf,
                    password_salt,
                    SALT_SIZE)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for password salt",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&enc_salt_buf,
                    enc_salt,
                    SALT_SIZE)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for enryption salt",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (InitUser(
      user,
      username,
      hashed_pass_buf,
      key_buf,
      hmac_salt_buf,
      password_salt_buf,
      enc_salt_buf,
      user_db_path,
      userconfig)),
    ERROR_SUCCESS,
    ERROR_USER_INIT,
    "failed to initialize user db path",
    rc,cleanup);

  rc = ERROR_SUCCESS;
cleanup:
  if (hmac_salt_buf) DestroyByteBuff_Secure(hmac_salt_buf);
  if (enc_salt_buf) DestroyByteBuff_Secure(enc_salt_buf);
  if (hashed_pass_buf) DestroyByteBuff_Secure(hashed_pass_buf);
  if (key_buf) DestroyByteBuff_Secure(key_buf);
  if (password_salt_buf)DestroyByteBuff_Secure(password_salt_buf);
  if (user_db_path)DestroyByteBuff_Secure(user_db_path);
  if (password_str){ 
    OPENSSL_cleanse(password_str,password_len);
    free(password_str);
  }
  OPENSSL_cleanse(hmac_salt, sizeof(hmac_salt));
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(password_salt, sizeof(password_salt));
  OPENSSL_cleanse(enc_salt, sizeof(enc_salt));
  OPENSSL_cleanse(hashed_pass, sizeof(hashed_pass));
  return rc;

}
int DestroyUser(user_t *user){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  if (user->hashed_pass) DestroyByteBuff_Secure(user->hashed_pass);
  if (user->password_salt) DestroyByteBuff_Secure(user->password_salt);
  if (user->hmac_salt) DestroyByteBuff_Secure(user->hmac_salt);
  if (user->user_db_path) DestroyByteBuff_Secure(user->user_db_path);
  if (user->username) DestroyByteBuff_Secure(user->username);
  if (user->key) DestroyByteBuff_Secure(user->key);

  OPENSSL_cleanse(user, sizeof(user_t));
  free(user);
  return ERROR_SUCCESS;
}
int LoadUser(user_t *user,const char *username){
  return ERROR_SUCCESS;
}
int SaveUser(user_t *user){
  return ERROR_SUCCESS;
}
int ChangeUserPass(user_t *user){
  return ERROR_SUCCESS;
}

int UserGetUsername(user_t *user,ByteBuff_t **username){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(username,user->username)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username buff");
  return ERROR_SUCCESS;
}
int UserGetKey(user_t *user,ByteBuff_t **key){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(key,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(key,user->key)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate key buff");
  return ERROR_SUCCESS;
}
int UserGetHmacSalt(user_t *user,ByteBuff_t **hmac_salt){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(hmac_salt,ERROR_NULL_VALUE_GIVEN,"NULL parameter");

  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(hmac_salt,user->hmac_salt)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate hmac_salt buff");
  return ERROR_SUCCESS;
}
int UserGetPasswordSalt(user_t *user,ByteBuff_t **password_salt){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(password_salt,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(password_salt,user->password_salt)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate password_salt buff");

  return ERROR_SUCCESS;
}

int UserGetHashedPass(user_t *user,ByteBuff_t **hashed_pass){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(hashed_pass,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(hashed_pass,user->hashed_pass)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate hashed pass buff");

    return ERROR_SUCCESS;

}

int UserGetDbPath(user_t *user, ByteBuff_t **user_db_path){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(user_db_path,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(user_db_path,user->user_db_path)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate user db path buff");
  return ERROR_SUCCESS;
}

int UserGetUserConf(user_t *user,UserConfig_t **userconf){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(userconf,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  MALLOC_CHECK_NULL_LOG(*userconf,
      sizeof(UserConfig_t),
      ERROR_MEMORY_ALLOCATION,
      "cannot allocate a copy user config struct");

  memcpy(*userconf,
      &user->userconf,
      sizeof(UserConfig_t));
  return ERROR_SUCCESS;
}
