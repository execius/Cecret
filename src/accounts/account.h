#ifndef ACCOUNTS_H
#define ACCOUNTS_H
#include "includes.h" 
#include "encryption.h"
#include "bytebuffer.h" 
#include "bytebuffer.h" 
#include "user.h" 


typedef struct EncryptedAccount_s EncryptedAccount_t;
typedef struct Account_s Account_t;

int InitAccount(Account_t **account
    ,const char *username
    ,const char *password
    ,const char *email
    ,const char *platform
    ,const char *note
    ,ByteBuff_t *iv);

enum AccErrors
{ 
  ERROR_ACCOUNT_INNIT_FAILURE = -9000
};

#endif /* ifndef ACCOUNTS_H */
