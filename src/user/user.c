#include "user.h"



int InitUser(user_t **user,const char *username,const char *password,UserConfig_t userconfig){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(username,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(password,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  MALLOC_CHECK_NULL_LOG(*user,sizeof(user_t),ERROR_MEMORY_ALLOCATION,
                        "cannot allocate user");
  ERROR_CHECK_SUCCESS_LOG((strlen(username) >= STRMAX),
                          1,
                          LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
                          "username lenght is larger than string lenght limit");
  
  ERROR_CHECK_SUCCESS_LOG((strlen(password) >= STRMAX),
                          1,
                          LOCKER_ERROR_STRING_LENGHT_ABOVE_MAX,
                          "password lenght is larger than string lenght limit");
  ERROR_CHECK_SUCCESS_LOG((snprintf((*user)->username, STRMAX-1, "%s",username) > 0),
                          1,
                          ERROR_STDLIB_FAILURE,
                          "failed to copy username into its field in the user struct");
  //TODO : hash then strore the password , the hashing algo is in the globalconfig
  // ERROR_CHECK_SUCCESS_LOG((snprintf(user->password, STRMAX, "%s",password) > 0),
  //                         1,
  //                         ERROR_STDLIB_FAILURE,
  //                         "failed to copy password into its field in the user struct");
  (*user)->user_db_id = 0 ;
  memcpy(&(*user)->userconf,&userconfig,sizeof(UserConfig_t));
  return ERROR_SUCCESS;
}
int DestroyUser(user_t *user){
ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"NULL parameter");
  free(user);
  return ERROR_SUCCESS;
}
int LoadUser(user_t *user,const char *username){
  return ERROR_SUCCESS;
}
int SaveUser(user_t *user){
  return ERROR_SUCCESS;
}
int ChangeUserPass(user_t *user){
  return ERROR_SUCCESS;
}
