#ifndef USRCONF_H
#define USRCONF_H
#include "includes.h"
#include "encryption.h"

typedef struct UserConfig_s {
  EncryptionOption_t encryption_option;
  HashOption_t hashing_option;
  HashOption_t hashing_option_keyed;
} UserConfig_t;  
#endif
