#include "account.h"

typedef struct EncryptedAccount_s {

  ByteBuff_t *username_cipher;
  ByteBuff_t *email_cipher;
  ByteBuff_t *password_cipher;
  ByteBuff_t *platform_cipher;
  ByteBuff_t *note_cipher;
  /*used for decryption*/
  ByteBuff_t *iv;

  /*these are used for lookup*/
  unsigned char username_hash[STRMAX];
  unsigned char platform_hash[STRMAX];
  unsigned char email_hash[STRMAX];


} EncryptedAccount_t;

typedef struct Account_s {
  char username[STRMAX];
  char password[STRMAX];
  char email[STRMAX];
  char platform[STRMAX];
  char note[STRMAX];
  /*used for encryption*/
  ByteBuff_t *iv;
}Account_t ;

int InitAccount(Account_t **account
    ,const char *username
    ,const char *password
    ,const char *email
    ,const char *platform
    ,const char *note
    ,ByteBuff_t *iv)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0 ;
  MALLOC_CHECK_NULL_LOG(*account,sizeof(Account_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate user");


  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (strlen(username) >= STRMAX),
      1,
      LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
      "username lenght is larger than string lenght limit",
      failure_len);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (snprintf((*account)->username,
                STRMAX-1, "%s",username) > 0),
      1,
      ERROR_STDLIB_FAILURE,
      "failed to copy username into user struct",
      failure_stdlib);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (strlen(password) >= STRMAX),
      1,
      LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
      "password lenght is larger than string lenght limit",
      failure_len);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (snprintf((*account)->password,
                STRMAX-1, "%s",password) > 0),
      1,
      ERROR_STDLIB_FAILURE,
      "failed to copy username into user struct",
      failure_stdlib);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (strlen(email) >= STRMAX),
      1,
      LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
      "email lenght is larger than string lenght limit",
      failure_len);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (snprintf((*account)->email,
                STRMAX-1, "%s",email) > 0),
      1,
      ERROR_STDLIB_FAILURE,
      "failed to copy username into user struct",
      failure_stdlib);
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (strlen(platform) >= STRMAX),
      1,
      LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
      "platform lenght is larger than string lenght limit",
      failure_len);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (snprintf((*account)->platform,
                STRMAX-1, "%s",platform) > 0),
      1,
      ERROR_STDLIB_FAILURE,
      "failed to copy username into user struct",
      failure_stdlib);
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (strlen(note) >= STRMAX),
      1,
      LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
      "note lenght is larger than string lenght limit",
      failure_len);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (snprintf((*account)->note,
                STRMAX-1, "%s",note) > 0),
      1,
      ERROR_STDLIB_FAILURE,
      "failed to copy username into user struct",
      failure_stdlib);
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (DupByteBuff(&(*account)->iv,iv)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to copy user iv into user struct",
      failure_dupbuff);

  return ERROR_SUCCESS;
failure_len:
  rc = LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX;
  goto cleanup;
failure_dupbuff:
  rc = ERROR_BUFFDUP_FAILURE;
  goto cleanup;
failure_stdlib:
  rc = ERROR_STDLIB_FAILURE;
  goto cleanup;
cleanup:
  if (*account){
    OPENSSL_cleanse(*account, sizeof(Account_t));
    free(*account);
  }
  return rc;
}
int CreateAccount(Account_t **account,
    const char *username,
    const char *password,
    const char *email,
    const char *platform,
    const char *note,
    user_t *user)
{
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ByteBuff_t *iv_buf = NULL;
  UserConfig_t *userconf =  NULL;
  unsigned char *iv = NULL;
  int rc = 0 , iv_len = 0;
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (UserGetUserConf(user,&userconf)),
      ERROR_SUCCESS,
      ERROR_GETUSRCONF_FAILURE,
      "error getting user config struct",
      failure_getusrconf);


  iv_len= EVP_CIPHER_get_iv_length(
      encryption_options_fetchers[userconf->encryption_option_idx]());

  MALLOC_CHECK_NULL_LOG(iv,
      iv_len,
      ERROR_MEMORY_ALLOCATION,
      "error allocating memory for account IV");

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (RAND_bytes(
                  iv,
                  iv_len
                 )),
      LIBSSL_SUCCESS,
      ERROR_LIBSSL_FAILURE,
      "failed to generate hmac salt",
      failure_libssl);



  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (InitByteBuff(&iv_buf,
                    iv,
                    (size_t)iv_len)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for hashed pass",
      failure_initbuff);



  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (InitAccount(account,
                   username,
                   password,
                   email,
                   platform,
                   note,
                   iv_buf)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize account",
      failure_initacc);

  rc = ERROR_SUCCESS;
  goto cleanup;
failure_getusrconf:
  rc = ERROR_GETUSRCONF_FAILURE;
  goto cleanup;
failure_libssl:
  rc = ERROR_LIBSSL_FAILURE;
  goto cleanup;
failure_initbuff:
  rc = ERROR_BUFFINIT_FAILURE;
  goto cleanup;
failure_initacc:
  rc = ERROR_ACCOUNT_INNIT_FAILURE;
  goto cleanup;
cleanup:
  OPENSSL_cleanse(iv,iv_len);
  if (iv) free(iv);
  if (iv_buf) DestroyByteBuff_Secure(iv_buf);
  if (userconf) free(userconf);
  return rc;
}
int DestroyAccount(Account_t *account){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  DestroyByteBuff_Secure(account->iv);
  OPENSSL_cleanse(account, sizeof(Account_t));
  free(account);
  return ERROR_SUCCESS;
}


