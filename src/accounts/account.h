#ifndef ACCOUNTS_H
#define ACCOUNTS_H
#include "includes.h" 


typedef struct EncryptedAccount_s EncryptedAccount_t;
typedef struct Account_s Account_t;

#include "encryption.h"
#include "hashing.h"
#include "bytebuffer.h" 
#include "bytebuffer.h" 
#include "user.h" 

int DestroyAccount(Account_t *account);

int CreateAccount(Account_t **account
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note
    ,user_t *user);

int AccountGetUsername(Account_t *account,ByteBuff_t **username);
int AccountGetPassword(Account_t *account,ByteBuff_t **password);
int AccountGetEmail(Account_t *account,ByteBuff_t **email);
int AccountGetPlatform(Account_t *account,ByteBuff_t **platform);
int AccountGetNote(Account_t *account,ByteBuff_t **note);


int DestroyEncryptedAccount(EncryptedAccount_t *account);
int InitEncryptedAccount(EncryptedAccount_t **account 
    ,const EncryptionField_t *username_cipher
    ,const EncryptionField_t *password_cipher
    ,const EncryptionField_t *email_cipher
    ,const EncryptionField_t *platform_cipher
    ,const EncryptionField_t *note_cipher
    ,const HashingField_t *username_hash
    ,const HashingField_t *platform_hash
    ,const HashingField_t *email_hash);


int EncryptedAccountGetUsernameHash(EncryptedAccount_t *eac,
    ByteBuff_t **username_hash);
int EncryptedAccountGetUsernameHash(EncryptedAccount_t *eac,
    ByteBuff_t **platform_hash);
int EncryptedAccountGetEmailHash(EncryptedAccount_t *eac,
    ByteBuff_t **email_hash);


int EncryptAccount(Account_t *account
    ,EncryptedAccount_t **eac
    ,user_t *user);

enum AccErrors
{ 
  ERROR_ACCOUNT_INNIT_FAILURE = -9000,
  ERROR_ENCACCOUNT_INNIT_FAILURE = -9001,
  ERROR_ENCACCOUNT_FAILURE = -9002
};

#endif /* ifndef ACCOUNTS_H */
