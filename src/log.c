#include <errno.h>
#include <fcntl.h>
#include <stdio.h> // mkdir
#include <stdlib.h> // exit
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h> // close
#include <assert.h>
#include <sys/stat.h>
#include "log.h"

static bool   log_initialized = false;
static int    log_last_file_index = 0;
static int    log_fd = -1;
static char  *log_buffer = NULL;
static size_t log_buffer_used = 0;
static size_t log_buffer_size = 0;
static bool   log_failed = false;
static size_t log_total_size = 0;
static size_t log_dir_limit_mb = 0;
static size_t log_file_limit_b = 0;
static char   log_dir[1<<12];

void log_choose_file_name(char *dst, size_t max, bool startup)
{
	size_t prev_size = -1;
	for (;;) {

		int num = snprintf(dst, max, "%s/log_%d.txt", log_dir, log_last_file_index);
		if (num < 0 || (size_t) num >= max) {
			write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		dst[num] = '\0';

		struct stat buf;
		if (stat(dst, &buf)) {
			if (errno == ENOENT)
				break;
			write_format_to_stderr("log_failed: %s (%s:%d)\n", strerror(errno), __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		prev_size = (size_t) buf.st_size;

		if (log_last_file_index == 100000000) {
			write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		log_last_file_index++;
	}

	// At startup don't create a new log file if the last one didn't reache its limit
	if (startup && prev_size < log_file_limit_b) {

		log_last_file_index--;

		int num = snprintf(dst, max, "%s/log_%d.txt", log_dir, log_last_file_index);
		if (num < 0 || (size_t) num >= max) {
			write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		dst[num] = '\0';
	}
}

void log_init(string dir, size_t dir_limit_mb, size_t file_limit_b, size_t buffer_size)
{
	// Copy args to "local" variables
	if (dir.size >= sizeof(log_dir))
		log_fatal(LIT("Log directory is too long\n"));
	memcpy(log_dir, dir.data, dir.size);
	log_dir[dir.size] = '\0';
	log_buffer_size = buffer_size;
	log_dir_limit_mb = dir_limit_mb;
	log_file_limit_b = file_limit_b;

	log_buffer = mymalloc(log_buffer_size);
	if (log_buffer == NULL) {
		write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	if (mkdir(log_dir, 0755) && errno != EEXIST) {
		write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	char name[1<<12];
	log_choose_file_name(name, sizeof(name), true);
	if (log_failed) return; 

	log_fd = open(name, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (log_fd < 0) {
		write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	log_total_size = 0;

	DIR *d = opendir(log_dir);
	if (d == NULL) {
		write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}
	struct dirent *dir_entry;
	while ((dir_entry = readdir(d))) {

		if (!strcmp(dir_entry->d_name, ".") || !strcmp(dir_entry->d_name, ".."))
			continue;

		char path[1<<12];
		int k = snprintf(path, SIZEOF(path), "%s/%s", log_dir, dir_entry->d_name);
		if (k < 0 || k >= SIZEOF(path)) log_fatal(LIT("Bad format"));
		path[k] = '\0';

		struct stat buf;
		if (stat(path, &buf))
			log_fatal(LIT("Couldn't stat log file"));

		if ((size_t) buf.st_size > SIZE_MAX - log_total_size)
			log_fatal(LIT("Log file is too big"));
		log_total_size += (size_t) buf.st_size;
	}
	closedir(d);

	static_assert(SIZEOF(size_t) > 4, "It's assumed size_t can store a number of bytes in the order of 10gb");
	if (log_total_size > log_dir_limit_mb * 1024 * 1024) {
		write_string_to_stderr(LIT("Log reached disk limit at startup\n"));
		log_failed = true;
		return;
	}

	log_initialized = true;
}

void log_free(void)
{
	if (log_initialized) {
		log_flush();
		if (log_fd > -1)
			close(log_fd);
		myfree(log_buffer, log_buffer_size);
		log_fd = -1;
		log_buffer = NULL;
		log_buffer_used = 0;
		log_buffer_size = 0;
		log_failed = false;
		log_file_limit_b = 0;
		log_dir_limit_mb = 0;
		log_dir[0] = '\0';
		log_initialized = false;
	}
}

bool log_empty(void)
{
	return log_failed || log_buffer_used == 0;
}

void log_flush(void)
{
	if (!log_initialized || log_failed || log_buffer_used == 0)
		return;

	/*
	 * Rotate the file if the limit was reached
	 */
	struct stat buf;
	if (fstat(log_fd, &buf)) {
		write_format_to_stderr("log_failed: %s (%s:%d)\n", strerror(errno), __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	if (buf.st_size + log_buffer_used >= log_file_limit_b) {

		char name[1<<12];
		log_choose_file_name(name, SIZEOF(name), false);
		if (log_failed) return; 

		close(log_fd);
		log_fd = open(name, O_WRONLY | O_APPEND | O_CREAT, 0644);
		if (log_fd < 0) {
			write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
	}

	/*
	 * Buffer is full. We need to flush it to continue
	 */
	int zeros = 0;
	size_t copied = 0;
	while (copied < log_buffer_used) {

		int num = write(log_fd, log_buffer + copied, log_buffer_used - copied);
		if (num < 0) {
			if (errno == EINTR)
				continue;
			write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}

		if (num == 0) {
			zeros++;
			if (zeros == 1000) {
				write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
				log_failed = true;
				return;
			}
		} else {
			zeros = 0;
		}

		copied += num;
		log_total_size += num;

		if (log_total_size > log_dir_limit_mb * 1024 * 1024) {
			write_string_to_stderr(LIT("Log reached disk limit\n"));
			log_failed = true;
			return;
		}
	}

	assert(copied == log_buffer_used);
	log_buffer_used = 0;
}

void log_fatal(string str)
{
	log_data(str);
	exit(-1);
}

void log_format(const char *fmt, ...)
{
	if (!log_initialized) {
		va_list args;
		va_start(args, fmt);
		write_format_to_stderr_va(fmt, args);
		va_end(args);
		return;
	}

	if (log_failed)
		return;

	if (log_buffer_used == log_buffer_size) {
		log_flush();
		if (log_failed) return;
	}

	int num;
	{
		va_list args;
		va_start(args, fmt);
		num = vsnprintf(log_buffer + log_buffer_used, log_buffer_size - log_buffer_used, fmt, args);
		va_end(args);
	}

	if (num < 0 || (size_t) num > log_buffer_size) {
		write_format_to_stderr("log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	if ((size_t) num > log_buffer_size - log_buffer_used) {
		
		log_flush();
		if (log_failed) return;

		va_list args;
		va_start(args, fmt);
		int k = vsnprintf(log_buffer + log_buffer_used, log_buffer_size - log_buffer_used, fmt, args);
		va_end(args);

		if (k != num) log_fatal(LIT("Bad format"));
	}

	log_buffer_used += num;
}

void log_data(string str)
{
	if (!log_initialized) {
		fwrite(str.data, 1, str.size, stdout);
		return;
	}

	if (log_failed)
		return;

	if (str.size > log_buffer_size)
		str = LIT("Log message was too long to log");

	if (str.size > log_buffer_size - log_buffer_used) {
		log_flush();
		if (log_failed) return;
	}
	assert(str.size <= log_buffer_size - log_buffer_used);

	assert(log_buffer);
	memcpy(log_buffer + log_buffer_used, str.data, str.size);
	log_buffer_used += str.size;
}

void log_perror(string str)
{
	if (!log_initialized)
		write_format_to_stderr("%.*s: %s\n", (int) str.size, str.data, strerror(errno));
	else
		log_format("%.*s: %s\n", (int) str.size, str.data, strerror(errno));
}
