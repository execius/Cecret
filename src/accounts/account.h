#ifndef ACCOUNTS_H
#define ACCOUNTS_H
#include "includes.h" 
#include "encryption.h"

typedef struct Account_s {
  char username[STRMAX];
  char email[STRMAX];
  char platform[STRMAX];
  char note[STRMAX];
}Account_t ;

typedef struct EncryptedAccount_s {

  EncryptedBuff_t username_cipher;
  EncryptedBuff_t email_cipher;
  EncryptedBuff_t password_cipher;
  EncryptedBuff_t platform_cipher;
  EncryptedBuff_t note_cipher;

  /*these are used for lookup*/
  char username_hash[STRMAX];
  char platform_hash[STRMAX];
  char email_hash[STRMAX];


} EncryptedAccount_t;

#endif /* ifndef ACCOUNTS_H */
