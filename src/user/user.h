#ifndef USER_H
#define USER_H
#include "includes.h" 
#include "usersconfig.h"

typedef struct user_s {
  char username[STRMAX];
  unsigned char hashed_pass[STRMAX];
  unsigned char usersalt[STRMAX];
  long int user_db_id;
  UserConfig_t userconf;
} user_t;
int InitUser(user_t **user,
             const char *username,
             const char *password,
             UserConfig_t userconfig);
int DestroyUser(user_t *user);
int SaveUserToDB(user_t *);
int LoadUserFromDB(user_t *user,const char *username);
int ChangeUserPass(user_t *);
#endif
