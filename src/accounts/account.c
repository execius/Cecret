#include "account.h"

typedef struct EncryptedAccount_s {

  ByteBuff_t *username_cipher;
  ByteBuff_t *email_cipher;
  ByteBuff_t *password_cipher;
  ByteBuff_t *platform_cipher;
  ByteBuff_t *note_cipher;
  /*used for decryption*/
  ByteBuff_t *iv;
  /*used for lookup*/
  ByteBuff_t *lookup_salt;

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
  /*used for lookup*/
  ByteBuff_t *lookup_salt;
}Account_t ;

int InitAccount(Account_t **account 
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note
    ,const ByteBuff_t *lookup_salt
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
  (*account)->username = NULL;
  (*account)->email = NULL;
  (*account)->password = NULL;
  (*account)->platform = NULL;
  (*account)->note = NULL;
  (*account)->iv = NULL;
  (*account)->lookup_salt = NULL;

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

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&(*account)->lookup_salt,lookup_salt)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate lookup_salt bytebuffer",
      rc,
      cleanup);



  rc = ERROR_SUCCESS;
  return rc;
cleanup:
  if (*account){
    DestroyAccount(*account);
  }
  *account = NULL;
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

  ByteBuff_t *iv_buf = NULL , *lookup_salt_buf = NULL;
  UserConfig_t *userconf =  NULL;
  unsigned char *iv = NULL;
  unsigned char *lookup_salt = NULL;
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

  MALLOC_CHECK_NULL_LOG(lookup_salt,
      SALT_SIZE,
      ERROR_MEMORY_ALLOCATION,
      "error allocating memory for account lookup salt");
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (RAND_bytes(
                  iv,
                  iv_len
                 )),
      LIBSSL_SUCCESS,
      ERROR_LIBSSL_FAILURE,
      "failed to generate iv",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (RAND_bytes(
                  lookup_salt,
                  SALT_SIZE
                 )),
      LIBSSL_SUCCESS,
      ERROR_LIBSSL_FAILURE,
      "failed to generate lookup salt",
      rc,
      cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&iv_buf,
                    iv,
                    (size_t)iv_len)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for iv",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitByteBuff(&lookup_salt_buf,
                    lookup_salt,
                    SALT_SIZE)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize byte buffer for lookup_salt",
      rc,
      cleanup);



  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitAccount(account,
                   username,
                   password,
                   email,
                   platform,
                   note,
                   lookup_salt_buf,
                   iv_buf)),
      ERROR_SUCCESS,
      ERROR_BUFFINIT_FAILURE,
      "failed to initialize account",
      rc,
      cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (iv){
    OPENSSL_cleanse(iv,iv_len);
    free(iv);
  }
  if (lookup_salt){
    OPENSSL_cleanse(lookup_salt,SALT_SIZE);
    free(lookup_salt);
  }
  if (iv_buf){
    DestroyByteBuff_Secure(iv_buf);
    free(iv_buf);
  }
  if (lookup_salt_buf){
    DestroyByteBuff_Secure(lookup_salt_buf);
    free(lookup_salt_buf);
  }
  if (userconf) free(userconf);
  return rc;
}
int DestroyAccount(Account_t *account){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  if (account->username)    DestroyByteBuff_Secure(account->username);
  if (account->password)    DestroyByteBuff_Secure(account->password);
  if (account->email)       DestroyByteBuff_Secure(account->email);
  if (account->platform)    DestroyByteBuff_Secure(account->platform);
  if (account->note)        DestroyByteBuff_Secure(account->note);
  if (account->iv)          DestroyByteBuff_Secure(account->iv);
  if (account->lookup_salt) DestroyByteBuff_Secure(account->lookup_salt);
  OPENSSL_cleanse(account, sizeof(Account_t));
  free(account);
  return ERROR_SUCCESS;
}


int AccountGetUsername(Account_t *account,ByteBuff_t **username){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(username,account->username)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username buff");
  return ERROR_SUCCESS;
}


int AccountGetPassword(Account_t *account,ByteBuff_t **password){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(password,account->password)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate password buff");
  return ERROR_SUCCESS;
}

int AccountGetEmail(Account_t *account,ByteBuff_t **email){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(email,account->email)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate email buff");
  return ERROR_SUCCESS;
}

int AccountGetPlatform(Account_t *account,ByteBuff_t **platform){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(platform,account->platform)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate platform buff");
  return ERROR_SUCCESS;
}


int AccountGetNote(Account_t *account,ByteBuff_t **note){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(note,account->note)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate note buff");
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
    ,const ByteBuff_t *lookup_salt
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
  ERROR_CHECK_NULL_LOG(lookup_salt,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_hash,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0 ;
  MALLOC_CHECK_NULL_LOG(*account,sizeof(EncryptedAccount_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate encrypted acc");
  (*account)->username_cipher = NULL;
  (*account)->password_cipher = NULL;
  (*account)->email_cipher = NULL;
  (*account)->platform_cipher = NULL;
  (*account)->note_cipher = NULL;
  (*account)->iv = NULL;
  (*account)->lookup_salt = NULL;
  (*account)->username_hash = NULL;
  (*account)->platform_hash = NULL;
  (*account)->email_hash = NULL;
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
      (DupByteBuff(&(*account)->lookup_salt,lookup_salt)), 
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate lookup_salt bytebuffer",
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
  return rc;
cleanup:
  if (*account){
    DestroyEncryptedAccount(*account);
    *account = NULL;
  }
  return rc;
}

int DestroyEncryptedAccount(EncryptedAccount_t *account){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  if (account->username_cipher)    DestroyByteBuff_Secure(account->username_cipher);
  if (account->password_cipher)    DestroyByteBuff_Secure(account->password_cipher);
  if (account->email_cipher)       DestroyByteBuff_Secure(account->email_cipher);
  if (account->platform_cipher)    DestroyByteBuff_Secure(account->platform_cipher);
  if (account->note_cipher)        DestroyByteBuff_Secure(account->note_cipher);
  if (account->iv)          DestroyByteBuff_Secure(account->iv);
  if (account->lookup_salt) DestroyByteBuff_Secure(account->lookup_salt);
  if (account->username_hash)    DestroyByteBuff_Secure(account->username_hash);
  if (account->platform_hash)    DestroyByteBuff_Secure(account->platform_hash);
  if (account->email_hash)       DestroyByteBuff_Secure(account->email_hash);
  OPENSSL_cleanse(account, sizeof(EncryptedAccount_t));
  free(account);
  return ERROR_SUCCESS;
}


int EncryptedAccountGetUsernameHash(EncryptedAccount_t *eac,
    ByteBuff_t **username_hash)
{
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username_hash,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(username_hash,eac->username_hash)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate username_hash buff");
  return ERROR_SUCCESS;
}

int EncryptedAccountGetPlatformHash(EncryptedAccount_t *eac,
    ByteBuff_t **platform_hash)
{
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(platform_hash,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(platform_hash,eac->platform_hash)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate platform_hash buff");
  return ERROR_SUCCESS;
}

int EncryptedAccountGetEmailHash(EncryptedAccount_t *eac,
    ByteBuff_t **email_hash)
{
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(email_hash,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (DupByteBuff(email_hash,eac->email_hash)),
      ERROR_SUCCESS,
      ERROR_BUFFDUP_FAILURE,
      "failed to duplicate email_hash buff");
  return ERROR_SUCCESS;
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
  ByteBuff_t *username_hash = NULL;
  ByteBuff_t *platform_hash = NULL;
  ByteBuff_t *email_hash = NULL;
  UserConfig_t *userconfig = NULL  ;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUserConf(user,&userconfig)),
      ERROR_SUCCESS,
      ERROR_GETUSRCONF_FAILURE,
      "error getting user config struct",
      rc,
      cleanup);

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

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_bytebuff(
       account->username,
       &username_hash,
       EVP_MD_size(hashing_options_fetchers[userconfig->lookup_hashing_option_idx]()),
       account->lookup_salt,
       hashing_options_fetchers[userconfig->lookup_hashing_option_idx](),
       globalconf->lookup_hash_iters)
     ),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash username for lookup",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_bytebuff(
       account->platform,
       &platform_hash,
       EVP_MD_size(hashing_options_fetchers[userconfig->lookup_hashing_option_idx]()),
       account->lookup_salt,
       hashing_options_fetchers[userconfig->lookup_hashing_option_idx](),
       globalconf->lookup_hash_iters)
     ),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash platform for lookup",
    rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_bytebuff(
       account->email,
       &email_hash,
       EVP_MD_size(hashing_options_fetchers[userconfig->lookup_hashing_option_idx]()),
       account->lookup_salt,
       hashing_options_fetchers[userconfig->lookup_hashing_option_idx](),
       globalconf->lookup_hash_iters)
     ),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash email for lookup",
    rc,cleanup);
  
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    
     (InitEncryptedAccount(
       eac,
       username_cipher,
       password_cipher,
       email_cipher,
       platform_cipher,
       note_cipher,
       account->iv,
       account->lookup_salt,
       username_hash,
       platform_hash,
       email_hash)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_INNIT_FAILURE,
    "failed to initialize encrypted account",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;

cleanup:
  if (platform_cipher) DestroyByteBuff_Secure(platform_cipher);
  if (password_cipher) DestroyByteBuff_Secure(password_cipher);
  if (email_cipher) DestroyByteBuff_Secure(email_cipher);
  if (username_cipher) DestroyByteBuff_Secure(username_cipher);
  if (note_cipher) DestroyByteBuff_Secure(note_cipher);
  if (platform_hash) DestroyByteBuff_Secure(platform_hash);
  if (username_hash) DestroyByteBuff_Secure(username_hash);
  if (email_hash) DestroyByteBuff_Secure(email_hash);
  if (userconfig) free(userconfig);
  return rc;
}


int DecryptAccount(EncryptedAccount_t *eac
    ,Account_t **account
    ,user_t *user)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");


  int rc = 0;
  ByteBuff_t *username = NULL;
  ByteBuff_t *email = NULL;
  ByteBuff_t *password = NULL;
  ByteBuff_t *platform = NULL;
  ByteBuff_t *note = NULL;
  UserConfig_t *userconfig = NULL  ;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUserConf(user,&userconfig)),
      ERROR_SUCCESS,
      ERROR_GETUSRCONF_FAILURE,
      "error getting user config struct",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptByteBuff(eac->username_cipher,
                       eac->iv,
                       &username,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt username byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptByteBuff(eac->password_cipher,
                       eac->iv,
                       &password,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt password byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptByteBuff(eac->email_cipher,
                       eac->iv,
                       &email,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt email byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptByteBuff(eac->platform_cipher,
                       eac->iv,
                       &platform,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt platform byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptByteBuff(eac->note_cipher,
                       eac->iv,
                       &note,
                       user)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt note byte buffer",
      rc,
      cleanup);

  
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    
     (InitAccount(
       account,
       username,
       password,
       email,
       platform,
       note,
       eac->lookup_salt,
       eac->iv)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_INNIT_FAILURE,
    "failed to initialize encrypted account",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;

cleanup:
  if (platform) DestroyByteBuff_Secure(platform);
  if (password) DestroyByteBuff_Secure(password);
  if (email) DestroyByteBuff_Secure(email);
  if (username) DestroyByteBuff_Secure(username);
  if (note) DestroyByteBuff_Secure(note);
  if (userconfig) free(userconfig);
  return rc;
}

