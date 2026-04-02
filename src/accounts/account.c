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
  ByteBuff_t *username_hash;
  ByteBuff_t *platform_hash;
  ByteBuff_t *email_hash;


} EncryptedAccount_t;

typedef struct Account_s {
  ByteBuff_t *username;
  ByteBuff_t *email;
  ByteBuff_t *password;
  ByteBuff_t *platform;
  ByteBuff_t *note;
  /*used for encryption*/
  ByteBuff_t *iv;
}Account_t ;

int InitAccount(Account_t **account 
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note
    ,const ByteBuff_t *iv)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0 ;
  MALLOC_CHECK_NULL_LOG(*account,sizeof(Account_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate user");
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->username,username)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->password,password)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate password bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->email,email)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate email bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->platform,platform)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate platform bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->note,note)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate note bytebuffer",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->iv,iv)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate iv bytebuffer",
      rc,
      cleanup);




  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (*account){
    OPENSSL_cleanse(*account, sizeof(Account_t));
    free(*account);
  }
  return rc;
}
int CreateAccount(Account_t **account
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note
    ,user_t *user)
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
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUserConf(user,&userconf)),
      ERROR_SUCCESS,
      ERROR_GETUSRCONF_FAILURE,
      "error getting user config struct",
      rc,
      cleanup);


  iv_len= EVP_CIPHER_get_iv_length(
      encryption_options_fetchers[userconf->encryption_option_idx]());

  MALLOC_CHECK_NULL_LOG(iv,
      iv_len,
      ERROR_MEMORY_ALLOCATION,
      "error allocating memory for account IV");

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (RAND_bytes(
                  iv,
                  iv_len
                 )),
      LIBSSL_SUCCESS,
      ERROR_LIBSSL_FAILURE,
      "failed to generate hmac salt",
      rc,
      cleanup);



  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&iv_buf,
                    iv,
                    (size_t)iv_len)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for hashed pass",
      rc,
      cleanup);



  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
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
      rc,
      cleanup);

  rc = ERROR_SUCCESS;
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






/*encrypted account stuff*/










int InitEncryptedAccount(EncryptedAccount_t **account 
    ,const ByteBuff_t *username_cipher
    ,const ByteBuff_t *password_cipher
    ,const ByteBuff_t *email_cipher
    ,const ByteBuff_t *platform_cipher
    ,const ByteBuff_t *note_cipher
    ,const ByteBuff_t *iv
    ,const ByteBuff_t *username_hash
    ,const ByteBuff_t *platform_hash
    ,const ByteBuff_t *email_hash)
{

  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(iv,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0 ;
  MALLOC_CHECK_NULL_LOG(*account,sizeof(EncryptedAccount_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate user");
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->username_cipher,username_cipher)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username_cipher bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->password_cipher,password_cipher)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate password_cipher bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->email_cipher,email_cipher)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate email_cipher bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->platform_cipher,platform_cipher)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate platform_cipher bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->note_cipher,note_cipher)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate note_cipher bytebuffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->iv,iv)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate iv bytebuffer",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->username_hash,username_hash)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username_hash bytebuffer",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->platform_hash,platform_hash)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate platform_hash bytebuffer",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->email_hash,email_hash)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate email_hash bytebuffer",
      rc,cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (*account){
    OPENSSL_cleanse(*account, sizeof(Account_t));
    free(*account);
  }
  return rc;
}


int EncryptAccount(Account_t *account
    ,EncryptedAccount_t **eac
    ,user_t *user)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");


  int rc = 0;
  ByteBuff_t *username_cipher = NULL;
  ByteBuff_t *email_cipher = NULL;
  ByteBuff_t *password_cipher = NULL;
  ByteBuff_t *platform_cipher = NULL;
  ByteBuff_t *note_cipher = NULL;
  // ByteBuff_t *username_hash;
  // ByteBuff_t *platform_hash;
  // ByteBuff_t *email_hash;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptByteBuff(account->username,
                       account->iv,
                       &username_cipher,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to encrypt username byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptByteBuff(account->password,
                       account->iv,
                       &password_cipher,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to encrypt password byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptByteBuff(account->email,
                       account->iv,
                       &email_cipher,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to encrypt email byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptByteBuff(account->platform,
                       account->iv,
                       &platform_cipher,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to encrypt platform byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptByteBuff(account->note,
                       account->iv,
                       &note_cipher,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to encrypt note byte buffer",
      rc,
      cleanup);

  // ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  //   (pkcs5_keyed_hash(
  //     password_str,
  //     password_len,
  //     key,
  //     ,
  //     SALT_SIZE,
  //     hashing_options_fetchers[userconfig.key_hashing_option_idx](),
  //     EVP_MD_size(hashing_options_fetchers[userconfig.hashing_option_idx]()),
  //     globalconf->key_derivation_iters)),
  //   ERROR_SUCCESS,
  //   ERROR_HASH_FAILED,
  //   "failed to derive encryption key",
  //   failure_hash);
  rc = ERROR_SUCCESS;
  goto cleanup;

cleanup:
  if (platform_cipher) DestroyByteBuff_Secure(platform_cipher);
  if (password_cipher) DestroyByteBuff_Secure(password_cipher);
  if (email_cipher) DestroyByteBuff_Secure(email_cipher);
  if (platform_cipher) DestroyByteBuff_Secure(platform_cipher);
  if (note_cipher) DestroyByteBuff_Secure(note_cipher);
  return rc;
}
