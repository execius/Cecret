#include "SqliteInterface.h"



int OpenDb(sqlite3 **db,const char *path){

  ERROR_CHECK_NULL_LOG(path,ERROR_NULL_VALUE_GIVEN,"null value in parameter");

  ERROR_CHECK_SUCCESS_LOG(
    (sqlite3_open(path,db)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    sqlite3_errmsg(*db));

  return ERROR_SUCCESS;
}

int make_master_db(void){
  char *err = NULL;
  char *master_db_filepath_str = NULL;
  ByteBuff_t *master_db_filepath = NULL;
  int rc = 0;
  sqlite3 *master;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (DupByteBuff(&master_db_filepath,
                    globalconf->master_db_dir_path)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to duplicate byte buff while building master db path",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (AppendStrByteBuff(master_db_filepath,"/master.db")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/master.db' while building master db path",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff_NullTerminated(master_db_filepath
                                      ,(unsigned char **)&master_db_filepath_str)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to get master db path null terminated str from byte buff",
      rc,cleanup);
  


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
  (OpenDb(&master,master_db_filepath_str)),
  ERROR_SUCCESS,
  ERROR_CANNOT_OPEN_DB,
  "cannot open db",
  rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_exec(master,
                  master_db_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    rc,cleanup);

  rc = ERROR_SUCCESS;
cleanup:
  if (master_db_filepath) DestroyByteBuff_Secure(master_db_filepath);
  if (master_db_filepath_str){ 
    OPENSSL_cleanse(master_db_filepath_str,strlen(master_db_filepath_str));
    free(master_db_filepath_str);
    }
  if (err) free(err);
  return rc;

}
int make_user_db(user_t *user){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  char *err = NULL  ;
  ByteBuff_t *username = NULL;
  ByteBuff_t *user_db_filepath = NULL;
  char *user_db_filepath_str = NULL;
  sqlite3 *user_db;
  int rc = 0;
  ERROR_CHECK_SUCCESS_LOG(
      (UserGetUsername(user,&username)),
      ERROR_SUCCESS,
      ERROR_USER_GET_USERNAME,
      "failed to get username from user");


  ERROR_CHECK_SUCCESS_LOG(
      (UserGetDbPath(user,&user_db_filepath)),
      ERROR_SUCCESS,
      ERROR_USER_GET_DBPATH,
      "failed to get user db filepath from user");
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (GetBuffByteBuff_NullTerminated(user_db_filepath
                                      ,(unsigned char **)&user_db_filepath_str)
       ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_NL_FAILURE,
      "failed to get user db path null terminated str from byte buff",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (OpenDb(&user_db,user_db_filepath_str)),
      ERROR_SUCCESS,
      ERROR_CANNOT_OPEN_DB,
      "cannot open user db",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_exec(user_db,
                  creds_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_exec(user_db,
                  configs_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    rc,cleanup);
  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (username) DestroyByteBuff_Secure(username);
  if (user_db_filepath) DestroyByteBuff_Secure(user_db_filepath);
  if (user_db_filepath_str) {
    OPENSSL_cleanse(user_db_filepath_str,strlen(user_db_filepath_str));
    free(user_db_filepath_str);
    }
  if (err) free(err);
  return rc;

}

int CloseDb(sqlite3 *db){

  ERROR_CHECK_NULL_LOG(db,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  sqlite3_close(db);

  return ERROR_SUCCESS;
}



int insert_user_db(sqlite3 *master,user_t *user){
  ERROR_CHECK_NULL_LOG(master,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ByteBuff_t *username = NULL,
             *user_db_filepath = NULL;
  unsigned char *username_serialized = NULL,
                *user_db_filepath_serialized = NULL;
  size_t user_db_filepath_serialized_length = 0 ,
         username_serialized_length = 0;
  int rc = 0;
  sqlite3_stmt *stmt;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_prepare_v2(master
                        ,insert_user_db_sql
                        ,-1
                        ,&stmt
                        ,NULL)
     ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "filed to preapare stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUsername(user,&username)),
      ERROR_SUCCESS,
      ERROR_USER_GET_USERNAME,
      "failed to get username from user",
     rc,cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetDbPath(user,&user_db_filepath)),
      ERROR_SUCCESS,
      ERROR_USER_GET_DBPATH,
      "failed to get user db filepath from user",
     rc,cleanup);
  
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(username
                         ,&username_serialized
                         ,&username_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize username",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(user_db_filepath
                         ,&user_db_filepath_serialized
                         ,&user_db_filepath_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize user_db_filepath",
      rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       1,
                       username_serialized,
                       username_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind username to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       2,
                       user_db_filepath_serialized,
                       user_db_filepath_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind user_db_filepath to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_step(stmt)),
    SQLITE_DONE,
    ERROR_SQLITE_FAILURE,
    "failed to step stmt",
    rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_finalize(stmt)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    "failed to finalize stmt",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
  if (username) 
    DestroyByteBuff_Secure(username);
  if (user_db_filepath) 
    DestroyByteBuff_Secure(user_db_filepath);
  if (username_serialized) {
    OPENSSL_cleanse(username_serialized
        ,username_serialized_length);
    free(username_serialized);
  }
  if (user_db_filepath_serialized) {
    OPENSSL_cleanse(user_db_filepath_serialized,
        user_db_filepath_serialized_length);
    free(user_db_filepath_serialized);
  }
  return rc;
}

int insert_config(sqlite3 *userdb,user_t *user){
  ERROR_CHECK_NULL_LOG(userdb,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  int rc = 0;
  ByteBuff_t *username = NULL,
             *lookup_salt = NULL,
             *hashed_pass_serialized_bb = NULL;
  HashingField_t *hashed_pass = NULL;
  unsigned char *username_serialized = NULL,
                *lookup_salt_serialized = NULL,
                *hashed_pass_serialized_bb_serialized = NULL;
  UserConfig_t *userconfig = NULL;
  size_t username_serialized_length = 0,
         lookup_salt_serialized_length = 0,
         hashed_pass_serialized_bb_serialized_length = 0;

  sqlite3_stmt *stmt;

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_prepare_v2(userdb
                        ,insert_config_sql
                        ,-1
                        ,&stmt
                        ,NULL)
     ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "filed to preapare stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUsername(user,&username)),
      ERROR_SUCCESS,
      ERROR_USER_GET_USERNAME,
      "failed to get username from user",
     rc,cleanup);


  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetDbPath(user,&lookup_salt)),
      ERROR_SUCCESS,
      ERROR_USER_GET_LOOKUPSALT,
      "failed to get lookup_salt from user",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetUserConf(user,&userconfig)),
      ERROR_SUCCESS,
      ERROR_GETUSRCONF_FAILURE,
      "failed to get userconfig from user",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (UserGetHashedPass(user,&hashed_pass)),
      ERROR_SUCCESS,
      ERROR_USER_GET_HASHED_PASS,
      "failed to get hashed_pass from user",
     rc,cleanup);

  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeHashingField(hashed_pass
                         ,&hashed_pass_serialized_bb)),
      ERROR_SUCCESS,
      ERROR_SERIALIZEHASHINGFIELD_FAILURE,
      "failed to serialize hashed_pass",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(hashed_pass_serialized_bb
                         ,&hashed_pass_serialized_bb_serialized
                         ,&hashed_pass_serialized_bb_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize hashedpass_bb",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(username
                         ,&username_serialized
                         ,&username_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize username",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
      (SerializeByteBuff(lookup_salt
                         ,&lookup_salt_serialized
                         ,&lookup_salt_serialized_length)),
      ERROR_SUCCESS,
      ERROR_SERIALIZATION_FAILURE,
      "failed to serialize lookup_salt",
      rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       1,
                       username_serialized,
                       username_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind username to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       2,
                       hashed_pass_serialized_bb_serialized,
                       hashed_pass_serialized_bb_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind hashedpass_bb to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_bind_blob(stmt,
                       3,
                       lookup_salt_serialized,
                       lookup_salt_serialized_length,
                       SQLITE_TRANSIENT)
                      ),
     SQLITE_OK,
     ERROR_SQLITE_FAILURE,
     "failed to bind lookup_salt to sql stmt",
     rc,cleanup);
  ERROR_CHECK_SUCCESS_SET_RC_GOTO_LOG(
    (sqlite3_step(stmt)),
    SQLITE_DONE,
    ERROR_SQLITE_FAILURE,
    "failed to step stmt",
    rc,cleanup);

  rc = ERROR_SUCCESS;
  goto cleanup;
cleanup:
   sqlite3_finalize(stmt),
  if (username) DestroyByteBuff_Secure(username);
  if (lookup_salt) DestroyByteBuff_Secure(lookup_salt);
  if (hashed_pass_serialized_bb) 
    DestroyByteBuff_Secure(hashed_pass_serialized_bb);

  if (username_serialized) {
    OPENSSL_cleanse(username_serialized
        ,username_serialized_length);
    free(username_serialized);
  }
  if (lookup_salt_serialized) {
    OPENSSL_cleanse(lookup_salt_serialized
        ,lookup_salt_serialized_length);
    free(lookup_salt_serialized);
  }
  if (hashed_pass_serialized_bb_serialized) {
    OPENSSL_cleanse(hashed_pass_serialized_bb_serialized
        ,hashed_pass_serialized_bb_serialized_length);
    free(hashed_pass_serialized_bb_serialized);
  }
  if (hashed_pass) 
    DestroyHashingField(hashed_pass);
  return rc;
}
