#ifndef CFORUM_BASIC_INCLUDED
#define CFORUM_BASIC_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
	char  *data;
	size_t size;
} string;

#define LIT(S) ((string) {.data=(S), .size=sizeof(S)-1})
#define STR(S) ((string) {.data=(S), .size=strlen(S)})
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define SIZEOF(X) ((int32_t) sizeof(X))
#define COUNTOF(X) (SIZEOF(X) / SIZEOF((X)[0]))
#define NULLSTR ((string) {.data=NULL, .size=0})

#ifndef NDEBUG
#define DEBUG(fmt, ...) write_format_to_stderr(fmt, ## __VA_ARGS__)
#else
#define DEBUG(...) {}
#endif

char     to_lower(char c);
bool     is_print(char c);
bool     is_pcomp(char c);
bool     is_digit(char c);
bool     is_alpha(char c);
bool     is_space(char c);

string trim(string s);
string substr(string str, size_t start, size_t end);
bool   streq(string s1, string s2);
bool   string_match_case_insensitive(string x, string y);
bool   endswith(string suffix, string name);
bool   startswith(string prefix, string str);
void   print_bytes(string prefix, string str);

void  *mymalloc(size_t num);
void   myfree(void *ptr, size_t num);

uint64_t get_real_time_ms(void);
uint64_t get_monotonic_time_ms(void);
uint64_t get_monotonic_time_ns(void);

bool write_string_to_stderr(string s);
bool write_format_to_stderr(const char *fmt, ...);
bool write_format_to_stderr_va(const char *fmt, va_list args);

bool   load_file_contents(string file, string *out);

#endif // CFORUM_BASIC_INCLUDED