#include "user.h"



int InitUser(user_t **user,
             const char *username
             ,const unsigned char *password
             ,UserConfig_t userconfig)
{
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  MALLOC_CHECK_NULL_LOG(*user,sizeof(user_t),ERROR_MEMORY_ALLOCATION,
                        "cannot allocate user");


  ERROR_CHECK_SUCCESS_GOTO_LOG((strlen(username) >= STRMAX),
                               1,
                               LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
                               "username lenght is larger than string lenght limit",
                               failure);
  
  ERROR_CHECK_SUCCESS_GOTO_LOG((strlen((const char *)password) >= STRMAX),
                               1,
                               LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
                               "password lenght is larger than string lenght limit",
                               failure);
  ERROR_CHECK_SUCCESS_GOTO_LOG((snprintf((*user)->username,
                                         STRMAX-1, "%s",username) > 0),
                               1,
                               ERROR_STDLIB_FAILURE,
                               "failed to copy username into user struct",
                               failure);
  ERROR_CHECK_SUCCESS_GOTO_LOG(RAND_bytes((*user)->enc_salt,
                                          userconfig.hashing_option.salt_size),
                               LIBSSL_SUCCESS,
                               ERROR_LIBSSL_FAILURE,
                               "failed to hash password",
                               failure);

  ERROR_CHECK_SUCCESS_GOTO_LOG(RAND_bytes((*user)->hmac_salt,
                                          userconfig.hashing_option.salt_size),
                               LIBSSL_SUCCESS,
                               ERROR_LIBSSL_FAILURE,
                               "failed to hash password",
                               failure);
  ERROR_CHECK_SUCCESS_GOTO_LOG(hash_not_keyed(password,
                                              strlen((const char *)password),
                                              (userconfig.hashing_option).digest,
                                              (*user)->hashed_pass,
                                              NULL),
                               ERROR_SUCCESS,
                               ERROR_LIBSSL_FAILURE,
                               "failed to hash password",
                               failure);

  memcpy(&(*user)->userconf,&userconfig,sizeof(UserConfig_t));
  (*user)->user_db_id = 0 ;
  return ERROR_SUCCESS;
failure:
  OPENSSL_cleanse((*user)->hashed_pass, STRMAX);
  OPENSSL_cleanse((*user)->enc_salt, STRMAX);
  OPENSSL_cleanse((*user)->hmac_salt, STRMAX);
  free(*user);
  return ERROR_USER_INIT;
}
int DestroyUser(user_t *user){
ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  OPENSSL_cleanse((user)->hashed_pass, STRMAX);
  OPENSSL_cleanse((user)->enc_salt, STRMAX);
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
