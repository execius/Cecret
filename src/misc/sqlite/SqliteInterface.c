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
  char master_db_filepath[3*STRMAX];
  sqlite3 *master;

  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (snprintf(master_db_filepath,
            3*STRMAX-1, "%s/%s",globalconf->master_db_dir_path,"master.db") > 0),
  1,
  ERROR_STDLIB_FAILURE,
  "failed to initialize user db path",
  failure_stdlib);


  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (OpenDb(&master,master_db_filepath)),
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

  return ERROR_SUCCESS;
failure_stdlib:
  if (err) free(err);
  return ERROR_STDLIB_FAILURE;
failure_sqlite:
  if (err) free(err);
  return ERROR_SQLITE_FAILURE;
}
int make_user_db(user_t *user){
  ERROR_CHECK_NULL_LOG(user,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  char *err = NULL , *username = NULL;
  char *user_db_filepath = NULL;
  sqlite3 *user_db;
    ERROR_CHECK_SUCCESS_LOG(
    (UserGetUsername(user,&username)),
    ERROR_SUCCESS,
    ERROR_USER_GET_USERNAME,
    "failed to initialize user db path");

  MALLOC_CHECK_NULL_LOG(user_db_filepath,3*STRMAX,ERROR_MEMORY_ALLOCATION,
                        "cannot allocate user db file path");

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (snprintf(user_db_filepath,
              3*STRMAX-1,
              "%s/%s/%s%s",
              globalconf->master_db_dir_path,
              username,
              username,
              ".db")
    > 0),
    1,
    ERROR_STDLIB_FAILURE,
    "failed to initialize user db path",
    failure_stdlib);


  ERROR_CHECK_SUCCESS_GOTO_LOG(
  (OpenDb(&user_db,user_db_filepath)),
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
  free(user_db_filepath);
  return ERROR_SUCCESS;
failure_stdlib:
  free(user_db_filepath);
  free(err);
  return ERROR_STDLIB_FAILURE;
failure_sqlite:
  free(user_db_filepath);
  free(err);
  return ERROR_SQLITE_FAILURE;

}

int CloseDb(sqlite3 *db){

  ERROR_CHECK_NULL_LOG(db,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  sqlite3_close(db);

  return ERROR_SUCCESS;
}
