#ifndef SQLTINTR
#define SQLTINTR
#include "includes.h"

int opendb(sqlite3 **db,const char *path,char *errmsg);
int closedb(sqlite3 *db);

#endif /* ifndef MACRO */
