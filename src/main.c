#include <signal.h>
#include <stdlib.h> // atexit
#include "log.h"
#include "http.h"
#include "config.h"
#include "endpoints.h"
#include "backtrace.h"

void termination_signal_handler(int signo) 
{
	(void) signo;
	http_stop();
}

int main(int argc, char **argv)
{
	atexit(log_free);

	(void) argc;
	(void) argv;

	{
		config_init();
		config_load(LIT("config.txt"));

		// Setup signal handlers for the crash log
		struct sigaction sa_crash;
		sa_crash.sa_handler = dump_backtrace;
		sigemptyset(&sa_crash.sa_mask);
		sa_crash.sa_flags = SA_RESTART | SA_NODEFER;
		sigaction(SIGSEGV, &sa_crash, NULL);
		sigaction(SIGABRT, &sa_crash, NULL);
		sigaction(SIGFPE,  &sa_crash, NULL);
		sigaction(SIGILL,  &sa_crash, NULL);

		// Setup signal handlers for graceful termination
		struct sigaction sa_term;
		sa_term.sa_handler = termination_signal_handler;
		sigemptyset(&sa_term.sa_mask);
		sa_term.sa_flags = SA_RESTART;
		sigaction(SIGTERM, &sa_term, NULL);
		sigaction(SIGQUIT, &sa_term, NULL);
		sigaction(SIGINT,  &sa_term, NULL);

		DEBUG("Signals configured\n");

		// Setup logging
		log_init(
			config_string(LIT("log_dir_path")),
			config_int(LIT("log_dir_limit_mb")),
			config_int(LIT("log_file_limit_b")),
			config_int(LIT("log_buff_size_b"))
		);
		DEBUG("Logger configured\n");

		HTTPConfig http_config = http_default_config();
		http_config.http_port       = config_int(LIT("http_port"));
		http_config.http_addr       = config_string(LIT("http_addr"));
		http_config.https_port      = config_int(LIT("https_port"));
		http_config.https_addr      = config_string(LIT("https_addr"));
		http_config.cert_file       = config_string(LIT("cert_file"));
		http_config.privkey_file    = config_string(LIT("privkey_file"));
		http_config.access_log      = config_bool(LIT("access_log"));
		http_config.show_io         = config_bool(LIT("show_io"));
		http_config.show_requests   = config_bool(LIT("show_requests"));
		http_config.max_connections = config_int(LIT("max_connections"));
		http_config.keep_alive_max_requests = config_int(LIT("keep_alive_max_requests"));
		http_config.connection_timeout_sec  = config_int(LIT("connection_timeout_sec"));
		http_config.closing_timeout_sec     = config_int(LIT("closing_timeout_sec"));
		http_config.request_timeout_sec     = config_int(LIT("request_timeout_sec"));
		http_config.log_flush_timeout_sec   = config_int(LIT("log_flush_timeout_sec"));
		http_config.respond = respond;
		http_init(http_config);

		init_endpoints();

		config_free();
	}

	log_data(LIT("starting\n"));
	http_loop();
	log_data(LIT("closing\n"));

	free_endpoints();
	http_free();
	log_free();
	return 0;
}
