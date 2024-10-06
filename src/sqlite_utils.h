#ifndef CFORUM_SQLITE_UTILS_INCLUDED
#define CFORUM_SQLITE_UTILS_INCLUDED

#include "sqlite3.h"

sqlite3_stmt *sqlite3_utils_prepare(sqlite3 *handle, const char *fmt, ...);
int           sqlite3_utils_rows_exist(sqlite3 *handle, const char *fmt, ...);
bool          sqlite3_utils_exec(sqlite3 *handle, const char *fmt, ...);
int           sqlite3_utils_fetch(sqlite3_stmt *stmt, char *types, ...);

#endif // CFORUM_SQLITE_UTILS_INCLUDED