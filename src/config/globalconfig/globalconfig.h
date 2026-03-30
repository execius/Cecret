#ifndef GLOBALCONF_H
#define GLOBALCONF_H

#include "encryption.h" 
typedef struct GlobalConf_s {

  uint16_t config_version;
  
  /*for easy and configurable access*/
  char master_db_dir_path[STRMAX];
  char backup_dir_path[STRMAX];

  /*iterations for key derivation / password hashing 
   * this is the basis of the password security model 
   * bcs as long as :
   * key_derivation_iters < password_hashing_iters
   * we're safe*/
  uint32_t key_derivation_iters;  
  uint32_t password_hashing_iters;
}GlobalConf_t ;
extern GlobalConf_t *globalconf;
#endif /* ifdef GLOBALCONF_H */
