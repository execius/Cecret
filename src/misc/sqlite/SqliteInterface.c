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

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (DupByteBuff(&master_db_filepath,
                    globalconf->master_db_dir_path)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDBUFF_FAILED,
      "failed to duplicate byte buff while building master db path",
      failure_dupbuff);
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (AppendStrByteBuff(master_db_filepath,"/master.db")
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to append '/master.db' while building master db path",
      failure_appstrbuf);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (GetBuffByteBuff_NullTerminated(master_db_filepath
                                      ,(unsigned char **)&master_db_filepath_str)
       ),
      ERROR_SUCCESS,
      ERROR_APPENDSTRBUFF_FAILED,
      "failed to get master db path null terminated str from byte buff",
      failure_getbuffbytebuff_nl);
  


  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (OpenDb(&master,master_db_filepath_str)),
  ERROR_SUCCESS,
  ERROR_CANNOT_OPEN_DB,
  "cannot open db",
  failure_sqlite);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (sqlite3_exec(master,
                  master_db_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    failure_sqlite);

cleanup:
  if (master_db_filepath) DestroyByteBuff_Secure(master_db_filepath);
  if (master_db_filepath_str){ 
    OPENSSL_cleanse(master_db_filepath_str,strlen(master_db_filepath_str));
    free(master_db_filepath_str);
    }
  if (err) free(err);
  return rc;
failure_sqlite:
  rc = ERROR_SQLITE_FAILURE;
  goto cleanup;
failure_appstrbuf:
  rc = ERROR_APPENDSTRBUFF_FAILED;
  goto cleanup;
failure_dupbuff:
  rc = ERROR_BUFFDUP_FAILURE;
  goto cleanup ;

failure_getbuffbytebuff_nl:
  rc = ERROR_GETBUFF_NL_FAILURE;
  goto cleanup ;

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
  
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (GetBuffByteBuff_NullTerminated(user_db_filepath
                                      ,(unsigned char **)&user_db_filepath_str)
       ),
      ERROR_SUCCESS,
      ERROR_GETBUFF_NL_FAILURE,
      "failed to get user db path null terminated str from byte buff",
      failure_getbuffbytebuff_nl);
  ERROR_CHECK_SUCCESS_GOTO_LOG(
      (OpenDb(&user_db,user_db_filepath_str)),
      ERROR_SUCCESS,
      ERROR_CANNOT_OPEN_DB,
      "cannot open user db",
      failure_sqlite);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (sqlite3_exec(user_db,
                  creds_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    failure_sqlite);

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (sqlite3_exec(user_db,
                  configs_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    failure_sqlite);
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

failure_getbuffbytebuff_nl:
  rc = ERROR_GETBUFF_NL_FAILURE;
  goto cleanup ;

failure_sqlite:
  rc = ERROR_SQLITE_FAILURE;
  goto cleanup;
}

int CloseDb(sqlite3 *db){

  ERROR_CHECK_NULL_LOG(db,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  sqlite3_close(db);

  return ERROR_SUCCESS;
}
