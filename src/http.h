#ifndef CFORUM_HTTP_INCLUDED
#define CFORUM_HTTP_INCLUDED

#include <stdint.h>
#include "basic.h"

typedef enum {
	URL_HOSTMODE_NAME,
	URL_HOSTMODE_IPV4,
	URL_HOSTMODE_IPV6,
} url_hostmode;

typedef struct {
	url_hostmode mode;
	union {
		uint32_t ipv4;
		uint16_t ipv6[8];
		string   name;
	};
	bool  no_port;
	uint16_t port;
} url_host;

typedef struct {
	string username;
	string password;
} url_userinfo;

typedef struct {
	url_host host;
	url_userinfo userinfo;
	string path;
	string query;
	string schema;
	string fragment;
} url_t;

enum {
	P_OK,
	P_INCOMPLETE,
	P_BADMETHOD,
	P_BADVERSION,
	P_BADHEADER,
	P_BADURL,
};

enum {
	T_CHUNKED  = 1 << 0,
	T_COMPRESS = 1 << 1,
	T_DEFLATE  = 1 << 2,
	T_GZIP     = 1 << 3,
};

typedef enum {
	M_GET,
	M_POST,
	M_HEAD,
	M_PUT,
	M_DELETE,
	M_CONNECT,
	M_OPTIONS,
	M_TRACE,
	M_PATCH,
} Method;

#define MAX_HEADERS 32

typedef struct {
	string name;
	string value;
} Header;

typedef struct {
	Method method;
	url_t  url;
	int    major;
	int    minor;
	int    nheaders;
	Header headers[MAX_HEADERS];
	string content;
} Request;

typedef struct Connection Connection;

typedef enum {
	R_STATUS,
	R_HEADER,
	R_CONTENT,
	R_COMPLETE,
} ResponseBuilderState;

typedef struct {
	ResponseBuilderState state;
	Connection *conn;
	bool failed;
	bool keep_alive;
	size_t content_length_offset;
	size_t content_offset;
} ResponseBuilder;

void   status_line(ResponseBuilder *b, int status);
void   add_header(ResponseBuilder *b, string header);
void   add_header_f(ResponseBuilder *b, const char *fmt, ...);
void   append_content_s(ResponseBuilder *b, string str);
void   append_content_f(ResponseBuilder *b, const char *fmt, ...);
string append_content_start(ResponseBuilder *b, size_t cap);
void   append_content_end(ResponseBuilder *b, size_t num);
bool   append_file(ResponseBuilder *b, string file);
bool   serve_file_or_dir(ResponseBuilder *b, string prefix, string docroot, string reqpath, string mime, bool enable_dir_listing);
int    match_path_format(string path, char *fmt, ...);
bool   get_query_string_param(string str, string key, string dst, string *out);
bool   get_cookie(Request *request, string name, string *out);

typedef struct {
	int    http_port;
	string http_addr;
	int    https_port;
	string https_addr;
	string cert_file;
	string privkey_file;
	bool access_log;
	bool show_io;
	bool show_requests;
	int max_connections;
	int keep_alive_max_requests;
	int connection_timeout_sec;
	int closing_timeout_sec;
	int request_timeout_sec;
	int log_flush_timeout_sec;
	void (*respond)(Request, ResponseBuilder*);
} HTTPConfig;

void http_init(HTTPConfig config);
void http_loop(void);
void http_free(void);
void http_stop(void);
HTTPConfig http_default_config(void);

#endif // CFORUM_HTTP_INCLUDED