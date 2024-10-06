#ifndef CFORUM_LOG_INCLUDED
#define CFORUM_LOG_INCLUDED

#include <stddef.h>
#include "basic.h"

void log_init(string dir, size_t dir_limit_mb, size_t file_limit_b, size_t buffer_size);
void log_free(void);
void log_data(string str);
void log_fatal(string str);
void log_perror(string str);
void log_format(const char *fmt, ...);
void log_flush(void);
bool log_empty(void);

#endif // CFORUM_LOG_INCLUDED