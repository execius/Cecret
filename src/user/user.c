#include "user.h"

typedef struct user_s {
  char username[STRMAX];
  char user_db_path[3*STRMAX];

  ByteBuff_t *hashed_pass;
  /*used for lookup*/
  ByteBuff_t *hmac_salt;
  ByteBuff_t *password_salt;
  UserConfig_t userconf;
} user_t;

int InitUser(user_t **user,
             const char *username
             ,ByteBuff_t *hashed_pass
             ,ByteBuff_t *hmac_salt
             ,ByteBuff_t *password_salt
             ,char *user_db_path
             ,UserConfig_t userconfig)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hashed_pass,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hmac_salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password_salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user_db_path,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  MALLOC_CHECK_NULL_LOG(*user,sizeof(user_t),ERROR_MEMORY_ALLOCATION,
                        "cannot allocate user");

  (*user)->hmac_salt = NULL;
  (*user)->password_salt = NULL;
  (*user)->hashed_pass = NULL;
  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (strlen(username) >= STRMAX),
    1,
    LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
    "username lenght is larger than string lenght limit",
    failure);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (snprintf((*user)->username,
              STRMAX-1, "%s",username) > 0),
    1,
    ERROR_STDLIB_FAILURE,
    "failed to copy username into user struct",
    failure);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (strlen(user_db_path) >= 3*STRMAX),
    1,
    LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
    "user db path lenght is larger than limit",
    failure);
  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (snprintf((*user)->user_db_path,
              3*STRMAX-1, "%s",user_db_path) > 0),
    1,
    ERROR_STDLIB_FAILURE,
    "failed to copy user user_db_path into user struct",
    failure);

    ERROR_CHECK_SUCCESS_GOTO_LOG(
    (DupByteBuff(&(*user)->hashed_pass,hashed_pass)),
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to copy user user_db_path into user struct",
    failure_dupbuff);

    ERROR_CHECK_SUCCESS_GOTO_LOG(
    (DupByteBuff(&(*user)->password_salt,password_salt)),
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to duplicate password_salt salt buff",
    failure_dupbuff);

    ERROR_CHECK_SUCCESS_GOTO_LOG(
    (DupByteBuff(&(*user)->hmac_salt,hmac_salt)),
    ERROR_SUCCESS,
    ERROR_BUFFDUP_FAILURE,
    "failed to duplicate hmac_salt buff",
    failure_dupbuff);

  memcpy(&(*user)->userconf,&userconfig,sizeof(UserConfig_t));

  return ERROR_SUCCESS;
failure_dupbuff:
  if ((*user)->hashed_pass) DestroyByteBuff((*user)->hashed_pass);
  if ((*user)->password_salt) DestroyByteBuff((*user)->password_salt);
  if ((*user)->hmac_salt) DestroyByteBuff((*user)->hmac_salt);
  OPENSSL_cleanse(*user, sizeof(user_t));
  free(*user);
  return ERROR_BUFFDUP_FAILURE;
failure:
  OPENSSL_cleanse(*user, sizeof(user_t));
  free(*user);
  return ERROR_USER_INIT;
}




int CreateUser(user_t **user
    ,const char *username
    ,const unsigned char *password
    ,UserConfig_t userconfig)

{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc;
  unsigned char hmac_salt[SALT_SIZE];
  unsigned char password_salt[SALT_SIZE];
  char user_db_path[3*STRMAX];
  unsigned char hashed_pass[STRMAX];
  ByteBuff_t *hmac_salt_buf = NULL,
             *password_salt_buf = NULL,
             *hashed_pass_buf = NULL; 


  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (RAND_bytes(
      hmac_salt,
      SALT_SIZE)),
    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "failed to generate hmac salt",
    failure_libssl);



  ERROR_CHECK_SUCCESS_GOTO_LOG(
    RAND_bytes(
      password_salt,
      SALT_SIZE),
    LIBSSL_SUCCESS,
    ERROR_LIBSSL_FAILURE,
    "failed to generate hmac salt",
    failure_libssl);


  ERROR_CHECK_SUCCESS_GOTO_LOG(
    pkcs5_keyed_hash(
      (const char *)password,
      strlen((const char *)password),
      hashed_pass,
      password_salt,
      SALT_SIZE,
      hashing_options_fetchers[userconfig.hashing_option_idx](),
      EVP_MD_size(hashing_options_fetchers[userconfig.hashing_option_idx]()),
      globalconf->password_hashing_iters),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash password",
    failure_hash);



  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (snprintf(
      user_db_path,
      3*STRMAX-1, "%s/%s/%s%s",
      globalconf->master_db_dir_path,
      "users",username,
      ".db")
    > 0),
    1,
    ERROR_STDLIB_FAILURE,
    "failed to initialize user db path",
    failure_stdlib);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (InitByteBuff(&hashed_pass_buf,
                    hashed_pass,
                    EVP_MD_size(
                      hashing_options_fetchers[userconfig.hashing_option_idx]()))),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for hashed pass",
      failure_initbuff);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (InitByteBuff(&hmac_salt_buf,
                    hmac_salt,
                    SALT_SIZE)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for hmac salt",
      failure_initbuff);
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (InitByteBuff(&password_salt_buf,
                    password_salt,
                    SALT_SIZE)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for password salt",
      failure_initbuff);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (InitUser(
      user,
      username,
      hashed_pass_buf,
      hmac_salt_buf,
      password_salt_buf,
      user_db_path,
      userconfig)),
    ERROR_SUCCESS,
    ERROR_USER_INIT,
    "failed to initialize user db path",
    failure_init);

  rc = ERROR_SUCCESS;
cleanup:
  if (hmac_salt_buf) DestroyByteBuff(hmac_salt_buf);
  if (hashed_pass_buf) DestroyByteBuff(hashed_pass_buf);
  if (password_salt_buf)DestroyByteBuff(password_salt_buf);
  OPENSSL_cleanse(hmac_salt, sizeof(hmac_salt));
  OPENSSL_cleanse(password_salt, sizeof(password_salt));
  OPENSSL_cleanse(hashed_pass, sizeof(hashed_pass));
  return rc;


failure_stdlib:
  rc = ERROR_STDLIB_FAILURE;
  goto cleanup;
failure_libssl:
  rc = ERROR_LIBSSL_FAILURE;
  goto cleanup;
failure_hash:
  rc =  ERROR_HASH_FAILED;
  goto cleanup;
failure_init:
  rc = ERROR_USER_INIT;
  goto cleanup;
failure_initbuff:
  rc = ERROR_BUFFINIT_FAILURE;
  goto cleanup;
}
int DestroyUser(user_t *user){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  if (user->hashed_pass) DestroyByteBuff(user->hashed_pass);
  if (user->password_salt) DestroyByteBuff(user->password_salt);
  if (user->hmac_salt) DestroyByteBuff(user->hmac_salt);

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

int UserGetUsername(user_t *user,char **username){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(
      ((*username = strdup(user->username))),
      ERROR_LIBSTR_FAILURE,
      "failed to duplicate username");
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
      "failed to duplicate hmac_salt buff");

  return ERROR_SUCCESS;
}

int UserGetHashedPass(user_t *user,ByteBuff_t **hashed_pass){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(hashed_pass,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(hashed_pass,user->hashed_pass)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate hmac_salt buff");

    return ERROR_SUCCESS;

}

int UserGetDbPath(user_t *user, char **user_db_path){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(user_db_path,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(
      (*user_db_path = strdup(user->user_db_path)),
      ERROR_LIBSTR_FAILURE,
      "failed to duplicate user db path");
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
