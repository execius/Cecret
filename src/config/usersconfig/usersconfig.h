#ifndef USRCONF_H
#define USRCONF_H
#include "includes.h"
typedef struct UserConfig_s  UserConfig_t;  
#include "encryption.h"

typedef struct UserConfig_s {
  Encryption_options_idx encryption_option_idx;
  hashing_options_idx hashing_option_idx;
  hashing_options_idx key_hashing_option_idx;
  hashing_options_idx lookup_hashing_option_idx;
} UserConfig_t;  
#endif
