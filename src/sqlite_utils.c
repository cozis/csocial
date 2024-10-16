#include <assert.h>
#include <stdarg.h>
#include "log.h"
#include "basic.h"
#include "sqlite_utils.h"

int sqlite3_utils_fetch(sqlite3_stmt *stmt, char *types, ...)
{
	va_list args;
	va_start(args, types);

	int step = sqlite3_step(stmt);
	if (step == SQLITE_DONE)
		return 1; // No more rows
	if (step != SQLITE_ROW)
		return -1; // Error occurred
	// Have a row
	for (int i = 0; types[i]; i++) {
		switch (types[i]) {

			case 'x': 
			*va_arg(args, const void**) = sqlite3_column_blob(stmt, i);
			*va_arg(args, size_t*) = sqlite3_column_bytes(stmt, i);
			break;

			case 's':
			{
				string *dst = va_arg(args, string*);
				dst->data = sqlite3_column_text(stmt, i);
				dst->size = sqlite3_column_bytes(stmt, i);;
			}
			break;

			case 'i': *va_arg(args, int*) = sqlite3_column_int(stmt, i); break;
			default: va_end(args); return -1;
		}
	}
	va_end(args);
	return 0;
}

static sqlite3_stmt *vprep(sqlite3 *handle, const char *fmt, va_list args)
{
	char   buffer[1 << 10];
	size_t copied = 0;

	char params[8]; // The size of this buffer determines the maximum 
					// number of parameters in a prepared query
	int num_params = 0;

	const char *stmt_str;
	size_t      stmt_len;

	size_t len = strlen(fmt);
	size_t cur = 0;

	while (cur < len && fmt[cur] != ':')
		cur++;

	if (cur == len) {
		stmt_str = fmt;
		stmt_len = len;
	} else {

		// The cursor refers to the first ':'

		if (cur >= sizeof(buffer)) {
			log_data(LIT("Statement text buffer is too small\n"));
			return NULL;
		}
		
		memcpy(buffer, fmt, cur);
		copied = cur;

		do {

			assert(fmt[cur] == ':');
			cur++;
			if (cur == len) {
				log_data(LIT("Missing type specifier after ':'\n"));
				return NULL;
			}
			
			char t = fmt[cur];
			if (t != 'i' && t != 's' && t != 'x') {
				log_format("Invalid type specifier '%c'\n", t);
				return NULL;
			}
			cur++;

			if (num_params == COUNTOF(params)) {
				log_format("Parameter limit reached (%d)\n", COUNTOF(params));
				return NULL;
			}
			params[num_params++] = t;

			if (copied+1 >= sizeof(buffer)) {
				log_data(LIT("Statement text buffer is too small\n"));
				return NULL;
			}
			buffer[copied++] = '?';

			size_t save = cur;

			while (cur < len && fmt[cur] != ':')
				cur++;

			size_t copying = cur - save;
			if (copied + copying >= sizeof(buffer)) {
				log_data(LIT("Statement text buffer is too small\n"));
				return NULL;
			}
			memcpy(buffer + copied, fmt + save, copying);
			copied += copying;

		} while (cur < len);

		assert(copied < sizeof(buffer));
		buffer[copied] = '\0';

		stmt_str = buffer;
		stmt_len = copied;
	}

	DEBUG("SQL: %.*s\n", (int) stmt_len, stmt_str);

	sqlite3_stmt *stmt;
	int code = sqlite3_prepare_v2(handle, stmt_str, stmt_len, &stmt, 0);
	if (code != SQLITE_OK) {
		log_format("Failed to prepare SQL statement (sqlite3: %s)\n", sqlite3_errmsg(handle));
		return NULL;
	}

	for (int i = 0; i < num_params; i++) {
		int code;
		switch (params[i]) {
			
			case 'i': 
			{
				int v = va_arg(args, int);
				code = sqlite3_bind_int (stmt, i+1, v); 
			}
			break;

			case 's': 
			{
				string str = va_arg(args, string);
				code = sqlite3_bind_text(stmt, i+1, str.data, str.size, NULL); 
			}
			break;
			
			case 'x': 
			{
				void  *ptr = va_arg(args, void*);
				size_t len = va_arg(args, size_t);
				code = sqlite3_bind_blob(stmt, i+1, ptr, len, NULL); 
			}
			break;
		}
		if (code != SQLITE_OK) {
			log_format("Failed to bind parameter %d to SQL statement (sqlite3: %s)\n", i+1, sqlite3_errmsg(handle));
			sqlite3_finalize(stmt);
			return NULL;
		}
	}

	return stmt;
}

sqlite3_stmt *sqlite3_utils_prepare(sqlite3 *handle, const char *fmt, ...)
{
	sqlite3_stmt *stmt;

	va_list args;
	va_start(args, fmt);
	stmt = vprep(handle, fmt, args);
	va_end(args);

	return stmt;
}

bool sqlite3_utils_exec(sqlite3 *handle, const char *fmt, ...)
{
	sqlite3_stmt *stmt;

	va_list args;
	va_start(args, fmt);
	stmt = vprep(handle, fmt, args);
	va_end(args);

	if (stmt == NULL)
		return false;

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		log_format("Failed to execute SQL statement (sqlite3: %s)\n", sqlite3_errmsg(handle));
		sqlite3_finalize(stmt);
		return false;
	}

	sqlite3_finalize(stmt);
	return true;
}

int sqlite3_utils_rows_exist(sqlite3 *handle, const char *fmt, ...)
{
	sqlite3_stmt *stmt;

	va_list args;
	va_start(args, fmt);
	stmt = vprep(handle, fmt, args);
	va_end(args);

	if (stmt == NULL)
		return -1;

	int step = sqlite3_step(stmt);
	if (step == SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return 1; // No rows exist
	}

	if (step == SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return 0; // Rows exist
	}

	log_format("Failed to execute SQL statement (sqlite3: %s)\n", sqlite3_errmsg(handle));
	sqlite3_finalize(stmt);
	return -1;
}
