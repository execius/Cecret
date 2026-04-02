#ifndef ACCOUNTS_H
#define ACCOUNTS_H
#include "includes.h" 


typedef struct EncryptedAccount_s EncryptedAccount_t;
typedef struct Account_s Account_t;

#include "encryption.h"
#include "bytebuffer.h" 
#include "bytebuffer.h" 
#include "user.h" 

int InitAccount(Account_t **account 
    ,const ByteBuff_t *username
    ,const ByteBuff_t *password
    ,const ByteBuff_t *email
    ,const ByteBuff_t *platform
    ,const ByteBuff_t *note
    ,const ByteBuff_t *iv);

enum AccErrors
{ 
  ERROR_ACCOUNT_INNIT_FAILURE = -9000
};

#endif /* ifndef ACCOUNTS_H */
