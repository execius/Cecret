#include "account.h"

typedef struct EncryptedAccount_s {

  EncryptionField_t *username_cipher;
  EncryptionField_t *email_cipher;
  EncryptionField_t *password_cipher;
  EncryptionField_t *platform_cipher;
  EncryptionField_t *note_cipher;

  /*these are used for lookup*/
  HashingField_t *username_hash;
  HashingField_t *platform_hash;
  HashingField_t *email_hash;


} EncryptedAccount_t;

typedef struct Account_s {
  EncryptionField_t *username;
  EncryptionField_t *email;
  EncryptionField_t *password;
  EncryptionField_t *platform;
  EncryptionField_t *note;
}Account_t ;

int InitAccount(Account_t **account 
    ,const EncryptionField_t *username
    ,const EncryptionField_t *password
    ,const EncryptionField_t *email
    ,const EncryptionField_t *platform
    ,const EncryptionField_t *note)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0 ;
  MALLOC_CHECK_NULL_LOG(*account,sizeof(Account_t),ERROR_MEMORY_ALLOCATION,
      "cannot allocate user");
  (*account)->username = NULL;
  (*account)->email = NULL;
  (*account)->password = NULL;
  (*account)->platform = NULL;
  (*account)->note = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->username,username)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate username encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->password,password)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate password encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->email,email)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate email encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->platform,platform)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate platform encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->note,note)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate note encryption field",
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
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;

  EncryptionField_t *username_ef = NULL;
  EncryptionField_t *password_ef = NULL;
  EncryptionField_t *email_ef = NULL;
  EncryptionField_t *platform_ef = NULL;
  EncryptionField_t *note_ef = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(&username_ef,
                    username,
                    user)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create encryption field for username",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(&password_ef,
                    password,
                    user)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create encryption field for password",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(&email_ef,
                    email,
                    user)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create encryption field for email",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(&platform_ef,
                    platform,
                    user)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create encryption field for platform",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (CreateEncryptionField(&note_ef,
                    note,
                    user)),
      ERROR_SUCCESS,
      ERROR_CREATEENCRYPTIONFIELD_FAILURE,
      "failed to create encryption field for note",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitAccount(account,
                   username_ef,
                   password_ef,
                   email_ef,
                   platform_ef,
                   note_ef)
       ),
      ERROR_SUCCESS,
      ERROR_ACCOUNT_INNIT_FAILURE,
      "failed to initialize account",
      rc,
      cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (username_ef) 
    DestroyEncryptionField(username_ef);
  if (password_ef) 
    DestroyEncryptionField(password_ef);
  if (email_ef) 
    DestroyEncryptionField(email_ef);
  if (platform_ef) 
    DestroyEncryptionField(platform_ef);
  if (note_ef) 
    DestroyEncryptionField(note_ef);
  // if (lookup_salt){
  //   OPENSSL_cleanse(lookup_salt,SALT_SIZE);
  //   free(lookup_salt);
  // }
  // if (lookup_salt_buf){
  //   DestroyByteBuff_Secure(lookup_salt_buf);
  // }
  // if (userconf) free(userconf);
  return rc;
}
int DestroyAccount(Account_t *account){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  if (account->username)    DestroyEncryptionField(account->username);
  if (account->password)    DestroyEncryptionField(account->password);
  if (account->email)       DestroyEncryptionField(account->email);
  if (account->platform)    DestroyEncryptionField(account->platform);
  if (account->note)        DestroyEncryptionField(account->note);
  OPENSSL_cleanse(account, sizeof(Account_t));
  free(account);
  return ERROR_SUCCESS;
}


int AccountGetUsername(Account_t *account,ByteBuff_t **username){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (EncryptionFieldGetText(account->username,username)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get username buff");
  return ERROR_SUCCESS;
}


int AccountGetPassword(Account_t *account,ByteBuff_t **password){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (EncryptionFieldGetText(account->password,password)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get password buff");
  return ERROR_SUCCESS;
}

int AccountGetEmail(Account_t *account,ByteBuff_t **email){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(email,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (EncryptionFieldGetText(account->email,email)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get email buff");
  return ERROR_SUCCESS;
}

int AccountGetPlatform(Account_t *account,ByteBuff_t **platform){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(platform,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (EncryptionFieldGetText(account->platform,platform)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get platform buff");
  return ERROR_SUCCESS;
}


int AccountGetNote(Account_t *account,ByteBuff_t **note){
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(note,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (EncryptionFieldGetText(account->note,note)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get note buff");
  return ERROR_SUCCESS;
}

/*encrypted account stuff*/










int InitEncryptedAccount(EncryptedAccount_t **account 
    ,const EncryptionField_t *username_cipher
    ,const EncryptionField_t *password_cipher
    ,const EncryptionField_t *email_cipher
    ,const EncryptionField_t *platform_cipher
    ,const EncryptionField_t *note_cipher
    ,const HashingField_t *username_hash
    ,const HashingField_t *platform_hash
    ,const HashingField_t *email_hash)
{

  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_NULL_LOG(username_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(email_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(platform_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(note_cipher,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

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

  (*account)->username_hash = NULL;
  (*account)->platform_hash = NULL;
  (*account)->email_hash = NULL;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->username_cipher,username_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate username_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->password_cipher,password_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate password_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->email_cipher,email_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate email_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->platform_cipher,platform_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate platform_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupEncryptionField(&(*account)->note_cipher,note_cipher)), 
      ERROR_SUCCESS,
      ERROR_DUPENCRYPTIONFIELD_FAILURE,
      "failed to duplicate note_cipher encryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupHashingField(&(*account)->username_hash,username_hash)), 
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate username_hash encryption field",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupHashingField(&(*account)->platform_hash,platform_hash)), 
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate platform_hash encryption field",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupHashingField(&(*account)->email_hash,email_hash)), 
      ERROR_SUCCESS,
      ERROR_DUPHASHINGFIELD_FAILURE,
      "failed to duplicate email_hash encryption field",
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
  if (account->username_cipher)    DestroyEncryptionField(account->username_cipher);
  if (account->password_cipher)    DestroyEncryptionField(account->password_cipher);
  if (account->email_cipher)       DestroyEncryptionField(account->email_cipher);
  if (account->platform_cipher)    DestroyEncryptionField(account->platform_cipher);
  if (account->note_cipher)        DestroyEncryptionField(account->note_cipher);
  if (account->username_hash)    DestroyHashingField(account->username_hash);
  if (account->platform_hash)    DestroyHashingField(account->platform_hash);
  if (account->email_hash)       DestroyHashingField(account->email_hash);
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
      (HashingFieldGetText(eac->username_hash,username_hash)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "failed to get username_hash buff");
  return ERROR_SUCCESS;
}

int EncryptedAccountGetPlatformHash(EncryptedAccount_t *eac,
    ByteBuff_t **platform_hash)
{
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(platform_hash,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (HashingFieldGetText(eac->platform_hash,platform_hash)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "failed to get platform_hash buff");
  return ERROR_SUCCESS;
}

int EncryptedAccountGetEmailHash(EncryptedAccount_t *eac,
    ByteBuff_t **email_hash)
{
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_NULL_LOG(email_hash,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  ERROR_CHECK_SUCCESS_LOG(
      (HashingFieldGetText(eac->email_hash,email_hash)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "failed to get email_hash buff");
  return ERROR_SUCCESS;
}





int EncryptAccount(Account_t *account
    ,EncryptedAccount_t **eac
    ,user_t *user)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");


  int rc = 0;
  const EVP_CIPHER *type = NULL;
  const EVP_MD *digest = NULL;
  EncryptionField_t *username_cipher = NULL;
  EncryptionField_t *email_cipher = NULL;
  EncryptionField_t *password_cipher = NULL;
  EncryptionField_t *platform_cipher = NULL;
  EncryptionField_t *note_cipher = NULL;

  /*temporary for hashing*/
  HashingField_t *username_hf = NULL;
  HashingField_t *platform_hf = NULL;
  HashingField_t *email_hf = NULL;


  HashingField_t *username_hash = NULL;
  HashingField_t *platform_hash = NULL;
  HashingField_t *email_hash = NULL;
  UserConfig_t *userconfig = NULL  ;
  HashingField_t *key_hf = NULL  ;
  ByteBuff_t *lookup_salt = NULL  ;
  ByteBuff_t *key = NULL  ;
  ByteBuff_t *username = NULL  ;
  ByteBuff_t *email = NULL  ;
  ByteBuff_t *platform = NULL  ;

  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptionFieldGetText(account->username,&username)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get username buff",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptionFieldGetText(account->email,&email)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get email buff",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptionFieldGetText(account->platform,&platform)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTIONFIELD_GETTEXT_FAILURE,
      "failed to get platform buff",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetLookupSalt(user,&lookup_salt)),
      ERROR_SUCCESS,
      ERROR_USER_GET_LOOKUPSALT,
      "error getting user lookup_salt byte buffer",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetKey(user,&key_hf)),
      ERROR_SUCCESS,
      ERROR_USER_GET_KEY,
      "error getting user key hashing field",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (HashingFieldGetText(key_hf,&key)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "error getting user key byte buffer",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUserConf(user,&userconfig)),
      ERROR_SUCCESS,
      ERROR_GETUSRCONF_FAILURE,
      "error getting user config struct",
      rc,
      cleanup);
  type = encryption_options_fetchers[userconfig->encryption_option_idx]();
  digest = hashing_options_fetchers[userconfig->lookup_hashing_option_idx]();

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              account->username,
                              key,
                              &username_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt username byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              account->password,
                              key,
                              &password_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt password byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              account->email,
                              key,
                              &email_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt email byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              account->platform,
                              key,
                              &platform_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt platform byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (EncryptEncryptionField(type,
                              account->note,
                              key,
                              &note_cipher)),
      ERROR_SUCCESS,
      ERROR_ENCRYPTENCRYPTIONFIELD_FAILURE,
      "failed to encrypt note byte buffer",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitHashingField(&username_hf,
                        username,
                        lookup_salt)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to initialize hashing field ",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitHashingField(&email_hf,
                        email,
                        lookup_salt)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to initialize hashing field ",
      rc,cleanup);
ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (InitHashingField(&platform_hf,
                    platform,
                    lookup_salt)),
      ERROR_SUCCESS,
      ERROR_INITHASHINGFIELD_FAILURE,
      "failed to initialize hashing field ",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_HashingField(
       username_hf,
       &username_hash,
       EVP_MD_size(digest),
       digest,
       globalconf->lookup_hash_iters)
     ),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash username for lookup",
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_HashingField(
       platform_hf,
       &platform_hash,
       EVP_MD_size(digest),
       digest,
       globalconf->lookup_hash_iters)
     ),
    ERROR_SUCCESS,
    ERROR_HASH_FAILED,
    "failed to hash platform for lookup",
    rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (
     pkcs5_keyed_hash_HashingField(
       email_hf,
       &email_hash,
       EVP_MD_size(digest),
       digest,
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
  if (platform_cipher) DestroyEncryptionField(platform_cipher);
  if (password_cipher) DestroyEncryptionField(password_cipher);
  if (email_cipher) DestroyEncryptionField(email_cipher);
  if (username_cipher) DestroyEncryptionField(username_cipher);
  if (note_cipher) DestroyEncryptionField(note_cipher);
  if (platform_hash) DestroyHashingField(platform_hash);
  if (username_hash) DestroyHashingField(username_hash);
  if (email_hash) DestroyHashingField(email_hash);
  if (platform_hf) DestroyHashingField(platform_hf);
  if (username_hf) DestroyHashingField(username_hf);
  if (email_hf) DestroyHashingField(email_hf);
  if (key_hf) DestroyHashingField(key_hf);
  if (key) DestroyByteBuff_Secure(key);
  if (lookup_salt) DestroyByteBuff_Secure(lookup_salt);
  if (username) DestroyByteBuff_Secure(username);
  if (platform) DestroyByteBuff_Secure(platform);
  if (email) DestroyByteBuff_Secure(email);
  if (userconfig) free(userconfig);
  return rc;
}


int DecryptAccount(EncryptedAccount_t *eac
    ,Account_t **account
    ,user_t *user)
{
  ERROR_CHECK_NULL_LOG(account,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(eac,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");


  const EVP_CIPHER *type = NULL;
  int rc = 0;
  EncryptionField_t *username = NULL;
  EncryptionField_t *email = NULL;
  EncryptionField_t *password = NULL;
  EncryptionField_t *platform = NULL;
  EncryptionField_t *note = NULL;
  UserConfig_t *userconfig = NULL  ;
  HashingField_t *key_hf = NULL  ;
  ByteBuff_t *key = NULL  ;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetKey(user,&key_hf)),
      ERROR_SUCCESS,
      ERROR_USER_GET_KEY,
      "error getting user key hashing field",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (HashingFieldGetText(key_hf,&key)),
      ERROR_SUCCESS,
      ERROR_HASHINGFIELD_GETTEXT_FAILURE,
      "error getting user key byte buffer",
      rc,
      cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUserConf(user,&userconfig)),
      ERROR_SUCCESS,
      ERROR_GETUSRCONF_FAILURE,
      "error getting user config struct",
      rc,
      cleanup);

  type = encryption_options_fetchers[userconfig->encryption_option_idx]();
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->username_cipher,
                       key,
                       &username)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt username enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->password_cipher,
                       key,
                       &password)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt password enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->email_cipher,
                       key,
                       &email)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt email enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->platform_cipher,
                       key,
                       &platform)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt platform enryption field",
      rc,
      cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DecryptEncryptionField(type,
                       eac->note_cipher,
                       key,
                       &note)), 
      ERROR_SUCCESS,
      ERROR_ENCRYPTBYTEBUFF_FAILURE,
      "failed to decrypt note enryption field",
      rc,
      cleanup);



  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(

     (InitAccount(
       account,
       username,
       password,
       email,
       platform,
       note)
     ),
    ERROR_SUCCESS,
    ERROR_ENCACCOUNT_INNIT_FAILURE,
    "failed to initialize encrypted account",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;

cleanup:
  if (platform) DestroyEncryptionField(platform);
  if (password) DestroyEncryptionField(password);
  if (email) DestroyEncryptionField(email);
  if (username) DestroyEncryptionField(username);
  if (note) DestroyEncryptionField(note);
  if (key) DestroyByteBuff_Secure(key);
  if (key_hf) DestroyHashingField(key_hf);
  if (userconfig) free(userconfig);
  return rc;
}

