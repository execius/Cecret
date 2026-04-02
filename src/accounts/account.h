#ifndef ACCOUNTS_H
#define ACCOUNTS_H
#include "includes.h" 


typedef struct EncryptedAccount_s EncryptedAccount_t;
typedef struct Account_s Account_t;

#include "encryption.h"
#include "bytebuffer.h" 
#include "bytebuffer.h" 
#include "user.h" 

int DestroyAccount(Account_t *account);
int DestroyEncryptedAccount(EncryptedAccount_t *account);

int InitAccount(Account_t **account 
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note
    ,const ByteBuff_t *lookup_salt
    ,const ByteBuff_t *iv);

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
    ,const ByteBuff_t *email_hash);
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
