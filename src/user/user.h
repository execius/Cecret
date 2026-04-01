#ifndef USER_H
#define USER_H
#include "includes.h" 
#include "globalconfig.h"
#include "usersconfig.h"
#include "bytebuffer.h" 
#include "encryption.h"

typedef struct user_s user_t;

int InitUser(user_t **user
             ,ByteBuff_t *username
             ,ByteBuff_t *hashed_pass
             ,ByteBuff_t *hmac_salt
             ,ByteBuff_t *password_salt
             ,ByteBuff_t *user_db_path
             ,UserConfig_t userconfig);
int DestroyUser(user_t *user);
int SaveUserToDB(user_t *);
int LoadUserFromDB(user_t *user,const char *username);
int ChangeUserPass(user_t *);


/*the value given by any of the following functions
 * in the second argument should be passed to free
 * and preferably cleared with OPENSSL_cleanse 
 * before that*/
int UserGetUsername(user_t *user,ByteBuff_t **username);
int UserGetHmacSalt(user_t *user,ByteBuff_t **hmac_salt);
int UserGetPasswordSalt(user_t *user,ByteBuff_t **password_salt);
int UserGetHashedPass(user_t *user,ByteBuff_t **hashed_pass);
int UserGetDbPath(user_t *user, ByteBuff_t **user_db_path);
int UserGetUserConf(user_t *user,UserConfig_t **userconf);

enum  UserErrors
{ 
  ERROR_USER_INIT = - 3000,
  ERROR_USER_GET_USERNAME = -3001,
  ERROR_GETUSRCONF_FAILURE = -3002,
  ERROR_USER_GET_DBPATH = -3003
};

#endif
