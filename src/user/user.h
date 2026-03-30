#ifndef USER_H
#define USER_H
#include "includes.h" 
#include "globalconfig.h"
#include "usersconfig.h"
#include "encryption.h"

typedef struct user_s {
  char username[STRMAX];
  unsigned char hashed_pass[STRMAX];
  /*used for encryption*/
  unsigned char iv[STRMAX];
  /*used for lookup*/
  unsigned char hmac_salt[STRMAX];
  char user_db_path[3*STRMAX];
  UserConfig_t userconf;
} user_t;
int InitUser(user_t **user,
             const char *username
             ,const unsigned char *hashed_pass
             ,unsigned char *iv
             ,unsigned char *hmac_salt
             ,char *user_db_path
             ,UserConfig_t userconfig);
int DestroyUser(user_t *user);
int SaveUserToDB(user_t *);
int LoadUserFromDB(user_t *user,const char *username);
int ChangeUserPass(user_t *);
#endif
