#ifndef USER_H
#define USER_H

typedef struct user_s user_t;

#include "includes.h" 
#include "globalconfig.h"
#include "usersconfig.h"
#include "bytebuffer.h" 
#include "encryption.h"


int CreateUser(user_t **user
    ,ByteBuff_t *username
    ,ByteBuff_t *password
    ,UserConfig_t userconfig);
int DestroyUser(user_t *user);
int SaveUserToDB(user_t *);
int LoadUserFromDB(user_t *user,const ByteBuff_t *username);
int ChangeUserPass(user_t *usre,ByteBuff_t *newpassword);


/*the value given by any of the following functions
 * in the second argument should be passed to DestroyByteBuff_Secure 
 * or DestroyHashingField depending on the type
 * pass userconf to free , it has no sensitive data 
 * */
int UserGetUsername(user_t *user,ByteBuff_t **username);
int UserGetKey(user_t *user,HashingField_t **key);
int UserGetLookupSalt(user_t *user,ByteBuff_t **lookup_salt);
int UserGetPasswordSalt(user_t *user,ByteBuff_t **password_salt);
int UserGetHashedPass(user_t *user,HashingField_t **hashed_pass);
int UserGetDbPath(user_t *user, ByteBuff_t **user_db_path);
int UserGetUserConf(user_t *user,UserConfig_t **userconf);

enum  UserErrors
{ 
  ERROR_USER_INIT = - 3000,
  ERROR_USER_GET_USERNAME = -3001,
  ERROR_GETUSRCONF_FAILURE = -3002,
  ERROR_USER_GET_DBPATH = -3003,
  ERROR_USER_GET_KEY = -3004,
  ERROR_USER_GET_LOOKUPSALT = -3004

};

#endif
