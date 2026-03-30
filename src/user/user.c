#include "user.h"




/*the password MUST be null terminated !*/
int InitUser(user_t **user,
             const char *username
             ,const unsigned char *hashed_pass
             ,unsigned char *iv
             ,unsigned char *hmac_salt
             ,char *user_db_path
             ,UserConfig_t userconfig)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hashed_pass,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(hmac_salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user_db_path,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  MALLOC_CHECK_NULL_LOG(*user,sizeof(user_t),ERROR_MEMORY_ALLOCATION,
                        "cannot allocate user");


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

    memcpy(
    (*user)->hashed_pass,
    hashed_pass,
    EVP_MD_size(hashing_options_fetchers[userconfig.hashing_option_idx]()));

    memcpy(
    (*user)->iv,
    iv,
    EVP_CIPHER_iv_length(encryption_options_fetchers[userconfig.encryption_option_idx]()));

    memcpy(
    (*user)->hmac_salt,
    hmac_salt,
    EVP_MD_block_size(hashing_options_fetchers[userconfig.keyed_hashing_option_idx]()));

    memcpy(&(*user)->userconf,&userconfig,sizeof(UserConfig_t));


  return ERROR_SUCCESS;
failure:
  OPENSSL_cleanse((*user)->hashed_pass, STRMAX);
  OPENSSL_cleanse((*user)->iv, STRMAX);
  OPENSSL_cleanse((*user)->hmac_salt, STRMAX);
  free(*user);
  return ERROR_USER_INIT;
}

int CreateUser(void){

  // ERROR_CHECK_SUCCESS_GOTO_LOG(
  //   RAND_bytes((*user)->iv,
  //     EVP_CIPHER_iv_length(encryption_options_fetchers[userconfig.encryption_option_idx]())),
  //   LIBSSL_SUCCESS,
  //   ERROR_LIBSSL_FAILURE,
  //   "failed to generate encryption IV",
  //   failure);
  //
  //
  // ERROR_CHECK_SUCCESS_GOTO_LOG(
  //   RAND_bytes(
  //     (*user)->hmac_salt,
  //     /*note : i use block size as also salt size , so there's that*/
  //     EVP_MD_block_size(hashing_options_fetchers[userconfig.hashing_option_idx]())),
  //   LIBSSL_SUCCESS,
  //   ERROR_LIBSSL_FAILURE,
  //   "failed to generate hmac salt",
  //   failure);
  //
  // ERROR_CHECK_SUCCESS_GOTO_LOG(
  //   hash_not_keyed(
  //     password,
  //     strlen((const char *)password),
  //     hashing_options_fetchers[userconfig.hashing_option_idx](),
  //     (*user)->hashed_pass,
  //     NULL),
  //   ERROR_SUCCESS,
  //   ERROR_LIBSSL_FAILURE,
  //   "failed to hash password",
  //   failure);


  // ERROR_CHECK_SUCCESS_GOTO_LOG(
  //   (snprintf(
  //     (*user)->user_db_path,
  //     2*STRMAX-1, "%s/%s/%s%s",
  //     globalconf->master_db_dir_path,
  //     "users",username,
  //     ".db")
  //   > 0),
  //   1,
  //   ERROR_STDLIB_FAILURE,
  //   "failed to initialize user db path",
  //   failure);
    return ERROR_SUCCESS;

}
int DestroyUser(user_t *user){
ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  OPENSSL_cleanse((user)->hashed_pass, STRMAX);
  OPENSSL_cleanse((user)->iv, STRMAX);
  OPENSSL_cleanse((user)->hmac_salt, STRMAX);
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
