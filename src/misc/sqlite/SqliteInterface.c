#include "SqliteInterface.h"

int make_master_db(sqlite3 **db,const char *path,char *errmsg){
  const char *template =
    "\
CREATE TABLE master (\
id INTEGER PRIMARY KEY,\
username TEXT NOT NULL UNIQUE,\
db_path TEXT NOT NULL UNIQUE);";
}
int make_user_db(sqlite3 **db,const char *path,char *errmsg){
  const char *creds_template =
    "\
CREATE TABLE credentials (\
id INTEGER PRIMARY KEY,\
username_cipher BLOB NOT NULL ,\
email_cipher BLOB NOT NULL ,\
password_cipher BLOB NOT NULL ,\
platform_cipher BLOB NOT NULL ,\
note_cipher BLOB NOT NULL,\
username_hash BLOB NOT NULL ,\
platform_hash BLOB NOT NULL ,\
email_hash BLOB NOT NULL);\
CREATE INDEX idx_username_hash ON credentials(username_hash);\
CREATE INDEX idx_email_hash ON credentials(email_hash);\
CREATE INDEX idx_platform_hash ON credentials(platform_hash)";
  const char *configs_template =
    "\
CREATE TABLE configs (\
id INTEGER PRIMARY KEY CHECK (id = 1),\
username TEXT NOT NULL ,\
hashed_pass BLOB NOT NULL ,\
enc_salt BLOB NOT NULL ,\
hmac_salt BLOB NOT NULL ,\
\
encryption_algorithm_enum INTEGER ,\
\
hashing_algorithm_enum INTEGER ,\
\
keyed_hashing_algorithm_enum INTEGER );WITHOUT ROWID";\
}


int opendb(sqlite3 **db,const char *path,char *errmsg){

  ERROR_CHECK_NULL_LOG(path,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  ERROR_CHECK_SUCCESS_LOG(
    (sqlite3_open(path,db)),
    SQLITE_OK,
    ERROR_SQLITE_FAILURE,
    sqlite3_errmsg(*db));

  return ERROR_SUCCESS;
}
int closedb(sqlite3 *db){

  ERROR_CHECK_NULL_LOG(db,ERROR_NULL_VALUE_GIVEN,"null value in parameter");
  sqlite3_close(db);

  return ERROR_SUCCESS;
}
