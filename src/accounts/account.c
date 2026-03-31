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
    ,ByteBuff_t *iv
    ,int iv_size)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
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
    "username lenght is larger than string lenght limit",
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
    "username lenght is larger than string lenght limit",
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
    "username lenght is larger than string lenght limit",
    failure_len);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (snprintf((*account)->note,
              STRMAX-1, "%s",note) > 0),
    1,
    ERROR_STDLIB_FAILURE,
    "failed to copy username into user struct",
    failure_stdlib);
  DupByteBuff(&(*account)->iv,iv);

  return ERROR_SUCCESS;
failure_len:
  OPENSSL_cleanse(*account, sizeof(Account_t));
  free(*account);
  return LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX;
failure_stdlib:
  OPENSSL_cleanse(*account, sizeof(Account_t));
  free(*account);
  return ERROR_STDLIB_FAILURE;
}
// int CreateAccount(){}
int DestroyAccount(Account_t *account){

  DestroyByteBuff(account->iv);

  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  OPENSSL_cleanse(account, sizeof(Account_t));
  free(account);
  return ERROR_SUCCESS;
}


