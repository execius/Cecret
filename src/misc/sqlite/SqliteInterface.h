#ifndef SQLTINTR
#define SQLTINTR
#include "includes.h"
#include "globalconfig.h"
#include "user.h"

int OpenDb(sqlite3 **db,const char *path);
int CloseDb(sqlite3 *db);
int make_master_db(void);
int make_user_db(user_t *user);
enum SqliteInterErrors{
  ERROR_CANNOT_OPEN_DB = -4000,
  ERROR_SQLITE_FAILURE = -4001,
};

  const char *master_db_template =
    "\
CREATE TABLE master (\
id INTEGER PRIMARY KEY,\
username TEXT NOT NULL UNIQUE,\
db_path TEXT NOT NULL UNIQUE);";

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
lookup_salt BLOB NOT NULL ,\
\
encryption_option_idx INTEGER ,\
\
hashing_option_idx INTEGER ,\
\
key_hashing_option_idx INTEGER ,\
\
lookup_hashing_option_idx INTEGER );WITHOUT ROWID";


#endif /* ifndef MACRO */
