#include "http.h"
#include "basic.h"
#include "sqlite_utils.h"

typedef enum {
	TPT_INT,
	TPT_FLOAT,
	TPT_STRING,
	TPT_QUERY,
	TPT_LAST,
} TemplateParamType;

typedef struct {
	TemplateParamType type;
	string name;
	union {
		int64_t i;
		double  f;
		string  s;
		sqlite3_stmt *q;
	};
} TemplateParam;

bool append_template(ResponseBuilder *b, string file, TemplateParam *params);
