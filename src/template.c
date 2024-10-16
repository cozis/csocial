#include <assert.h>
#include "log.h"
#include "template.h"
#include "tinytemplate.h"

typedef struct {
	ResponseBuilder *b;
	TemplateParam *params;
} TemplateContext;

static void template_output_callback(void *userp, const char *str, size_t len)
{
	TemplateContext *c = userp;
	append_content_s(c->b, (string) {str, len});
}

static bool template_sqlstmt_param_callback(void *data, const char *key_, size_t len, tinytemplate_value_t *value)
{
	string key = {key_, len};
	sqlite3_stmt *stmt = data;
	int column_count = sqlite3_column_count(stmt);
	bool found = false;
	for (int i = 0; i < column_count; i++) {
		const char *tmp = sqlite3_column_name(stmt, i);
		string column_name = STR(tmp);
		if (streq(column_name, key)) {
			switch (sqlite3_column_type(stmt, i)) {
				case SQLITE_INTEGER: tinytemplate_set_int(value, sqlite3_column_int(stmt, i)); break;
				case SQLITE_FLOAT  : tinytemplate_set_float(value, sqlite3_column_double(stmt, i)); break;
				case SQLITE_TEXT   : tinytemplate_set_string(value, (char*) sqlite3_column_text(stmt, i), sqlite3_column_bytes(stmt, i)); break;
				case SQLITE_BLOB   : log_fatal(LIT("Can't provide a BLOB column to a template")); break;
				case SQLITE_NULL   : log_fatal(LIT("Can't provide a NULL column to a template")); break;
			}
			found = true;
			break;
		}
	}
	return found;
}

static bool template_next_callback(void *userp, tinytemplate_value_t *value)
{
	sqlite3_stmt *stmt = userp;
	int res = sqlite3_step(stmt);
	if (res != SQLITE_ROW) {
		sqlite3_reset(stmt);
		return false;
	}

	tinytemplate_set_dict(value, stmt, template_sqlstmt_param_callback);
	return true;
}

static bool template_param_callback(void *userp, const char *key, size_t len, tinytemplate_value_t *value)
{
	TemplateContext *c = userp;
	string param = {.data=key, .size=len};

	for (int i = 0; c->params[i].type != TPT_LAST; i++) {
		if (streq(param, c->params[i].name)) {
			switch (c->params[i].type) {
				case TPT_INT   : tinytemplate_set_int   (value, c->params[i].i); break;
				case TPT_FLOAT : tinytemplate_set_float (value, c->params[i].f); break;
				case TPT_STRING: tinytemplate_set_string(value, c->params[i].s.data, c->params[i].s.size); break;
				case TPT_QUERY : tinytemplate_set_array (value, c->params[i].q, template_next_callback); break;
				case TPT_LAST  : assert(0); break;
			}
			return true;
		}
	}
	return false;
}

bool append_template(ResponseBuilder *b, string file, TemplateParam *params)
{
	tinytemplate_status_t status;
	tinytemplate_instr_t program[1<<9];
	size_t num_instr;
	char errmsg[1<<9];

	string template_str;
	if (!load_file_contents(file, &template_str))
		return false;

	status = tinytemplate_compile(template_str.data, template_str.size, program, COUNTOF(program), &num_instr, errmsg, sizeof(errmsg));
	if (status != TINYTEMPLATE_STATUS_DONE) {
		log_format("Template Compile Error: %s", errmsg);
		myfree(template_str.data, template_str.size);
		return false;
	}

	TemplateContext context;
	context.b = b;
	context.params = params;
	status = tinytemplate_eval(template_str.data, program, &context, template_param_callback, template_output_callback, errmsg, sizeof(errmsg));
	if (status != TINYTEMPLATE_STATUS_DONE)
		log_format("Template Runtime Error: %s", errmsg);
	myfree(template_str.data, template_str.size);
	return true;
}
