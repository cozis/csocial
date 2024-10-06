#include <assert.h>
#include <stdlib.h> // exit
#include "log.h"
#include "config.h"

typedef enum {
	CE_INT,
	CE_STR,
	CE_BOOL,
} ConfigEntryType;

typedef struct {
	string name;
	ConfigEntryType type;
	union {
		uint32_t num;
		string   txt;
		bool     yes;
	};
} ConfigEntry;

string       config_content;
ConfigEntry *config_entries;
int          config_count;
int          config_capacity;

void make_char_printable(char *buf, size_t max, char c)
{
	(void) max;

	if (is_print(c)) {
		assert(max >= 4);
		buf[0] = '\'';
		buf[1] = c;
		buf[2] = '\'';
		buf[3] = '\0';
	} else {
		assert(max >= 5);
		static const char hextable[] = "0123456789abcdef";
		buf[0] = '0';
		buf[1] = 'x';
		buf[2] = hextable[(uint8_t) c >> 4];
		buf[3] = hextable[c & 0xf];
		buf[4] = '\0';
	}
}

bool config_parse(string content)
{
	char  *src = content.data;
	size_t len = content.size;
	size_t cur = 0;

	bool error = false;
	for (;;) {

		// Skip whitespace before the entry
		while (cur < len && is_space(src[cur]))
			cur++;
		
		if (cur == len)
			break;
		
		if (src[cur] == '#') {
			// Comment
			while (cur < len && src[cur] != '\n')
				cur++;
			if (cur < len) {
				assert(src[cur] == '\n');
				cur++;
			}
		} else {
		
			// Expecting an identifier
			if (!is_alpha(src[cur]) && src[cur] != '_') {
				char buf[5];
				make_char_printable(buf, sizeof(buf), src[cur]);
				// Configs are handled before logging, so we need to write to stderr here
				log_format("Could not parse config file (invalid character %s)\n", buf);
				error = true;
				break;
			}

			ConfigEntry entry;

			size_t name_start = cur;
			do
				cur++;
			while (cur < len && (is_alpha(src[cur]) || is_digit(src[cur]) || src[cur] == '_'));
			entry.name = substr(content, name_start, cur);

			while (cur < len && is_space(src[cur]) && src[cur] != '\n')
				cur++;

			if (cur == len) {
				log_format("Missing value after '%.*s' in config file\n", (int) entry.name.size, entry.name.data);
				error = true;
				break;
			}

			if (cur+2 < len
				&& src[cur+0] == 'y'
				&& src[cur+1] == 'e'
				&& src[cur+2] == 's'
				&& (cur+3 == len || is_space(src[cur+3]))) {
				entry.type = CE_BOOL;
				entry.yes = true;
				cur += 3;
			} else if (cur+1 < len
				&& src[cur+0] == 'n'
				&& src[cur+1] == 'o'
				&& (cur+2 == len || is_space(src[cur+2]))) {
				entry.type = CE_BOOL;
				entry.yes = false;
				cur += 2;
			} else if (src[cur] == '"') {
				cur++; // Skip the first double quote
				size_t value_start = cur;
				while (cur < len && src[cur] != '"')
					cur++;
				entry.type = CE_STR;
				entry.txt = substr(content, value_start, cur);
				if (cur < len) {
					assert(src[cur] == '"');
					cur++;
				}
			} else if (is_digit(src[cur])) {
				uint32_t value = 0;
				do {
					int d = src[cur] - '0';
					if (value > (UINT32_MAX - d) / 10) {
						log_format("Invalid value after '%.*s' in config file (Integer is too big)\n", (int) entry.name.size, entry.name.data);
						error = true;
						break;
					}
					value = value * 10 + d;
					cur++;
				} while (cur < len && is_digit(src[cur]));
				if (error) break;
				entry.type = CE_INT;
				entry.num = value;
			} else {
				size_t value_start = cur;
				while (cur < len && (is_print(src[cur]) && !is_space(src[cur])))
					cur++;
				entry.type = CE_STR;
				entry.txt = substr(content, value_start, cur);
			}

			if (config_count == config_capacity) {
				int   new_cap = MAX(2 * config_capacity, 32);
				void *new_ptr = mymalloc(new_cap * sizeof(ConfigEntry));
				if (new_ptr == NULL) {
					log_format("Couldn't load config file (out of memory)\n");
					error = true;
					break;
				}
				if (config_count > 0)
					memcpy(new_ptr, config_entries, config_count * sizeof(ConfigEntry));
				myfree(config_entries, config_capacity * sizeof(ConfigEntry));
				config_entries = new_ptr;
				config_capacity = new_cap;
			}
			config_entries[config_count++] = entry;

			// Skip the rest of the line
			while (cur < len && is_space(src[cur]) && src[cur] != '\n')
				cur++;

			if (cur < len && src[cur] == '#')
				while (cur < len && src[cur] != '\n')
					cur++;
			
			if (cur < len) {
				if (src[cur] != '\n') {
					char buf[5];
					make_char_printable(buf, sizeof(buf), src[cur]);
					log_format("Invalid character %s after '%.*s' entry in config file\n", buf, (int) entry.name.size, entry.name.data);
					error = true;
					break;
				}
				cur++;
			}
		}
	}

	if (error) config_free();
	return !error;
}

void config_init(void)
{
	config_content  = NULLSTR;
	config_entries  = NULL;
	config_count    = 0;
	config_capacity = 0;
}

bool config_load(string file)
{
	config_init();

	if (!load_file_contents(file, &config_content))
		log_fatal(LIT("Could not load config file\n"));

	if (!config_parse(config_content)) {
		return false;
	}

	return true;
}

void config_free(void)
{
	if (config_entries) {
		myfree(config_content.data, config_content.size);
		myfree(config_entries, config_capacity * sizeof(ConfigEntry));
		config_content  = NULLSTR;
		config_entries  = NULL;
		config_count    = 0;
		config_capacity = 0;
	}
}

ConfigEntry *config_any(string name)
{
	for (int i = 0; i < config_count; i++)
		if (streq(name, config_entries[i].name))
			return &config_entries[i];
	return NULL;
}

string config_string(string name)
{
	ConfigEntry *entry = config_any(name);
	if (entry == NULL) {
		log_format("Config entry '%.*s' is not defined\n", (int) name.size, name.data);
		exit(-1);
	}
	if (entry->type != CE_STR) {
		log_format("Config entry '%.*s' is not a string\n", (int) name.size, name.data);
		exit(-1);
	}
	return entry->txt;
}

uint32_t config_int(string name)
{
	ConfigEntry *entry = config_any(name);
	if (entry == NULL) {
		log_format("Config entry '%.*s' is not defined\n", (int) name.size, name.data);
		exit(-1);
	}
	if (entry->type != CE_INT) {
		log_format("Config entry '%.*s' is not a string\n", (int) name.size, name.data);
		exit(-1);
	}

	return entry->num;
}

bool config_bool(string name)
{
	ConfigEntry *entry = config_any(name);
	if (entry == NULL) {
		log_format("Config entry '%.*s' is not defined\n", (int) name.size, name.data);
		exit(-1);
	}
	if (entry->type != CE_BOOL) {
		log_format("Config entry '%.*s' is not a boolean\n", (int) name.size, name.data);
		exit(-1);
	}

	return entry->yes;
}
