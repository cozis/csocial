#define _GNU_SOURCE
#include <stdio.h> // snprintf
#include <dlfcn.h>
#include <fcntl.h> // O_WRONLY, O_APPEND, O_CREAT
#include <signal.h>
#include <unistd.h> // write
#include <execinfo.h>
#include "basic.h"
#include "backtrace.h"

#define BACKTRACE_FILE   "backtrace.txt"
#define BACKTRACE_LIMIT 30

void dump_backtrace(int signo)
{
	string signame;
	switch (signo) {
		case SIGSEGV: signame = LIT("Segmentation fault");       break;
		case SIGABRT: signame = LIT("Aborted");                  break;
		case SIGFPE:  signame = LIT("Floating-point exception"); break;
		case SIGILL:  signame = LIT("Illegal instruction");      break;
		default:      signame = LIT("Unknown signal");           break;
	}

	void *stack_buf[BACKTRACE_LIMIT];
	int num_stack = backtrace(stack_buf, COUNTOF(stack_buf));

	char buffer[4096];
	int used = snprintf(buffer, sizeof(buffer), "\n%.*s\nStack trace:\n", (int) signame.size, signame.data);

	for (int i = 0; i < num_stack; i++) {

		int n;
		Dl_info info;
		if (dladdr(stack_buf[i], &info) && info.dli_sname) {
			n = snprintf(buffer + used, sizeof(buffer) - used, "  #%d: %s (%p, %s)\n", i, info.dli_sname, info.dli_fbase, info.dli_fname);
		} else {
			n = snprintf(buffer + used, sizeof(buffer) - used, "  #%d: ??? (%p)\n", i, stack_buf[i]);
		}
		used = MIN(COUNTOF(buffer)-1, used + n);
	}

	int fd = open(BACKTRACE_FILE, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0) return;

	int cpy = 0;
	while (cpy < used) {
		int n = write(fd, buffer + cpy, used - cpy);
		if (n < 0) return;
		cpy += n;
	}

	close(fd);

	signal(signo, SIG_DFL);
	raise(signo);
}