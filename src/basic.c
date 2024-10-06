#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h> // snprintf
#include <stdlib.h> // malloc, free
#include <sys/stat.h>
#include "log.h"
#include "basic.h"

void *mymalloc(size_t num)
{
	return malloc(num);
}

void myfree(void *ptr, size_t num)
{
	(void) num;
	free(ptr);
}

uint64_t timespec_to_ms(struct timespec ts)
{
	if ((uint64_t) ts.tv_sec > UINT64_MAX / 1000)
		log_fatal(LIT("Time overflow\n"));
	uint64_t ms = ts.tv_sec * 1000;

	uint64_t nsec_part = ts.tv_nsec / 1000000;
	if (ms > UINT64_MAX - nsec_part)
		log_fatal(LIT("Time overflow\n"));
	ms += nsec_part;
	return ms;
}

uint64_t timespec_to_ns(struct timespec ts)
{
	if ((uint64_t) ts.tv_sec > UINT64_MAX / 1000000000)
		log_fatal(LIT("Time overflow\n"));
	uint64_t ns = ts.tv_sec * 1000000000;

	if (ns > UINT64_MAX - ts.tv_nsec)
		log_fatal(LIT("Time overflow\n"));
	ns += ts.tv_nsec;
	return ns;
}

uint64_t get_monotonic_time_ms(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret) log_fatal(LIT("Couldn't read monotonic time\n"));
	return timespec_to_ms(ts);
}

uint64_t get_monotonic_time_ns(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret) log_fatal(LIT("Couldn't read monotonic time\n"));
	return timespec_to_ns(ts);
}

uint64_t get_real_time_ms(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (ret) log_fatal(LIT("Couldn't read real time\n"));
	return timespec_to_ms(ts);
}

bool string_match_case_insensitive(string x, string y)
{
	if (x.size != y.size)
		return false;
	for (size_t i = 0; i < x.size; i++)
		if (to_lower(x.data[i]) != to_lower(y.data[i]))
			return false;
	return true;
}

char to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	else
		return c;
}

string trim(string s)
{
	size_t cur = 0;
	while (cur < s.size && is_space(s.data[cur]))
		cur++;

	if (cur == s.size) {
		s.data = "";
		s.size = 0;
	} else {
		s.data += cur;
		s.size -= cur;
		while (is_space(s.data[s.size-1]))
			s.size--;
	}
	return s;
}

string substr(string str, size_t start, size_t end)
{
	return (string) {
		.data = str.data + start,
		.size = end - start,
	};
}

bool is_digit(char c)
{
	return c >= '0' && c <= '9';
}

bool is_alpha(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool is_print(char c)
{
	return c >= 32 && c < 127;
}

bool is_pcomp(char c)
{
	return c != '/' && c != ':' && is_print(c);
}

bool streq(string s1, string s2)
{
	// TODO: What is s1.data or s2.data is NULL?
	return s1.size == s2.size && !memcmp(s1.data, s2.data, s1.size);
}

bool startswith(string prefix, string str)
{
	if (prefix.size > str.size)
		return false;
	// TODO: What is prefix.data==NULL or str.data==NULL?
	return !memcmp(prefix.data, str.data, prefix.size);
}

bool endswith(string suffix, string name)
{
	char *tail = name.data + (name.size - suffix.size);
	return suffix.size <= name.size && !memcmp(tail, suffix.data, suffix.size);
}

bool load_file_contents(string file, string *out)
{
	char copy[1<<12];
	if (file.size >= sizeof(copy)) {
		log_data(LIT("File path is larger than the static buffer\n"));
		return false;
	}
	memcpy(copy, file.data, file.size);
	copy[file.size] = '\0';

	int fd = open(copy, O_RDONLY);
	if (fd < 0)
		return false;

	struct stat buf;
	if (fstat(fd, &buf) || !S_ISREG(buf.st_mode)) {
		log_data(LIT("Couldn't stat file or it's not a regular file\n"));
		close(fd);
		return false;
	}
	size_t size = (size_t) buf.st_size;

	char *str = mymalloc(size);
	if (str == NULL) {
		log_data(LIT("out of memory\n"));
		close(fd);
		return false;
	}

	size_t copied = 0;
	while (copied < size) {
		int n = read(fd, str + copied, size - copied);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_perror(LIT("read"));
			close(fd);
			myfree(str, size);
			return false;
		}
		if (n == 0)
			break; // EOF
		copied += n;
	}
	if (copied != size) {
		log_format("Read %zu bytes from file but %zu were expected\n", copied, size);
		return false;
	}

	close(fd);

	*out = (string) {str, size};
	return true;
}


bool write_string_to_stderr(string s)
{
	int fd = STDERR_FILENO;
	size_t num = 0;
	while (num < s.size) {
		int ret = write(fd, s.data + num, s.size - num);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		num += ret;
	};
	return true;
}

bool write_format_to_stderr_va(const char *fmt, va_list args)
{
	char buf[1<<10];

	int num = vsnprintf(buf, sizeof(buf), fmt, args);
	if (num < 0) log_fatal(LIT("Invalid format"));

	string str = {buf, num};
	return write_string_to_stderr(str);
}

bool write_format_to_stderr(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	bool ok = write_format_to_stderr_va(fmt, args);
	va_end(args);
	return ok;
}
