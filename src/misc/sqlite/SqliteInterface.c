#include "SqliteInterface.h"



int opendb(sqlite3 **db,const char *path){

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
  sqlite3 *master;
  ERROR_CHECK_SUCCESS_LOG(
  (opendb(&master,globalconf->master_db_path)),
  ERROR_SUCCESS,
  ERROR_CANNOT_OPEN_DB,
  "cannot open db");

  ERROR_CHECK_SUCCESS_GOTO_LOG(
    (sqlite3_exec(master,
                  master_db_template,
                  NULL,
                  NULL,
                  &err)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    err,
    failure);

  return ERROR_SUCCESS;
failure:
  free(err);
  closedb(master);
  return ERROR_SQLITE_FAILURE;
}
int make_user_db(sqlite3 **db){
  return ERROR_SUCCESS;

}

int closedb(sqlite3 *db){

  ERROR_CHECK_NULL_LOG(db,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  sqlite3_close(db);

  return ERROR_SUCCESS;
}
