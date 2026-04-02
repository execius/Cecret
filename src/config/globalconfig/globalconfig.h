#ifndef GLOBALCONF_H
#define GLOBALCONF_H

#include "encryption.h" 
#include "bytebuffer.h" 
typedef struct GlobalConf_s {

  uint16_t version;
  
  /*for easy and configurable access*/
  ByteBuff_t *master_db_dir_path;
  ByteBuff_t *backup_dir_path;

  uint32_t key_derivation_iters;  
  uint32_t lookup_hash_iters;  
  uint32_t password_hashing_iters;
}GlobalConf_t ;
extern GlobalConf_t *globalconf;

int InitGlobalConf(void);

#endif /* ifdef GLOBALCONF_H */
