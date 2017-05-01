#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <error.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef PTRACE_LIVEDUMP
#define PTRACE_LIVEDUMP 0x4221
#endif
#ifndef PT_LIVEDUMP
#define PT_LIVEDUMP PTRACE_LIVEDUMP
#endif

#ifdef HAVE_LINUX_OOM_H
#include <linux/oom.h>
#else
#define OOM_DISABLE -17
#define OOM_ADJUST_MIN -16
#define OOM_ADJUST_MAX 15
#endif

#ifdef HAVE_LINUX_LIVEDUMP_H
#include <linux/livedump.h>
#else
struct livedump_param {
  int sched_nice;
  int io_prio;
  int oom_adj;
  bool core_limit_set;
  unsigned long core_limit;
};
#endif

long
parse_numeric (char *arg)
{
  char *p;
  long val;

  val = strtol(arg, &p, 10);
  if (val == LONG_MAX)
    error(1, 0, "invalid number '%s'", arg);
  else if (*p || errno)
    error(1, errno, "not a number '%s'", arg);
  return val;
}

void
usage (void)
{
  fprintf (stderr, "usage: %s [options] pid [pid..]\n", program_invocation_short_name);
  fprintf (stderr, "Options are:\n");
  fprintf (stderr, "  -f, --force-limit=[NR,unlimited]\n"
	           "        force maximum core file size to NR bytes or unlimited\n");
  fprintf (stderr, "  -i, --io-priority=prio       set I/O priority\n");
  fprintf (stderr, "  -o, --oom-adjustment=adj     set OOM killer adjustment\n");
  fprintf (stderr, "  -s, --sched-nice=nice        set scheduling niceness\n");
  fprintf (stderr, "Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
  exit (1);
}

static bool parm_set = false;
static bool limit_set = false;
static bool limit_unlimited = false;
static bool ioprio_set = false;
static bool oom_set = false;
static bool nice_set = false;
static struct livedump_param param = {0, 0, 0, false, 0};
static struct option pcoredump_options[] = {
	{"force-limit", required_argument, 0, 'f'},
	{"io-priority", required_argument, 0, 'i'},
	{"oom-adjustment", required_argument, 0, 'o'},
	{"sched-nice", required_argument, 0, 's'},
	{ NULL }
};

static void
handle_option(int opt, char *arg)
{
	long val;

	switch (opt) {
	case 'f':
		if (!strcmp(optarg, "unlimited")) {
			param.core_limit = RLIM_INFINITY;
			limit_unlimited = true;
		} else {
			val = parse_numeric(optarg);
			if (val < 0 || val > RLIM_INFINITY)
				error(1, 0,
				      "invalid core file size limit %ld - must be [1:%ld]\n", 
				      val, RLIM_INFINITY);
			param.core_limit = val;
		}
		parm_set = true;
		param.core_limit_set = true;
		limit_set = true;
		break;

	case 'i':
		val = parse_numeric(optarg);
		if (val < 0 || val > 7)
			error(1, 0,
			      "invalid IO priority %ld - must be in range [0:7]",
			      val);
		param.io_prio = val;
		if (val)
			parm_set = true;
		ioprio_set = true;
		break;

	case 'o':
		val = parse_numeric(optarg);
		if (val < OOM_DISABLE || val > OOM_ADJUST_MAX)
			error(1, 0,
			      "invalid OOM adjustment %ld - must be in range [%d:%d]",
			      val, OOM_DISABLE, OOM_ADJUST_MAX);
		param.oom_adj = val;
		if (val)
			parm_set = true;
		oom_set = true;
		break;

	case 's':
		val = parse_numeric(optarg);
		if (val < -20 || val > 19)
			error(1, 0,
			      "invalid scheduling niceness %ld - must be in range [-20:19]",
			      val);
		param.sched_nice = val;
		if (val)
			parm_set = true;
		nice_set = true;
		break;

	default:
		usage();
	}
}

char *strdupcat(char *a, const char *a1, const char *b, ...)
{
	char *rv;
	unsigned int blen, alen = 0;
	va_list ap;
	char dummy[1];

	va_start(ap, b);
	blen = vsnprintf(dummy, 0, b, ap);
	va_end(ap);

	if (a)
		alen = strlen(a) + strlen(a1);

	rv = malloc(alen + blen + 1);
	if (!rv)
		error(1, ENOMEM, "Out of memory allocating command string");

	if (a) {
		strcat(rv, a);
		free(a);
		strcat(rv, a1);
	}

	va_start(ap, b);
	vsprintf(rv + alen, b, ap);
	va_end(ap);

	return rv;
}

static int
proc_livedump_pids(int *pids, unsigned int nr_pids)
{
	char *cmd = NULL;
	unsigned int i;
	size_t count;
	int ret = 0;

	if (limit_unlimited)
		cmd = strdupcat(cmd, " ", "core_limit=unlimited");
	else if (limit_set)
		cmd = strdupcat(cmd, " ", "core_limit=%lu", param.core_limit);

	if (ioprio_set)
		cmd = strdupcat(cmd, " ", "io_prio=%d", param.io_prio);

	if (oom_set)
		cmd = strdupcat(cmd, " ", "oom_adj=%d", param.oom_adj);

	if (nice_set)
		cmd = strdupcat(cmd, " ", "sched_prio=%d", param.sched_nice);

	cmd = strdupcat(cmd, "", "\n");

	count = strlen(cmd);

	for (i = 0; i < nr_pids; i++) {
		int fd = -1;
		char *fname = NULL;
		ssize_t rv;

		fname = strdupcat(fname, "", "/proc/%d/livedump", pids[i]);
		fd = open(fname, O_WRONLY);
		if (fd == -1) {
			error(0, errno, "Unable to open %s", fname);
			ret = 1;
			goto next;
		}
		rv = write(fd, cmd, count);
		if (rv != count) {
			error(0, errno, "Error writing to %s", fname);
			ret = 1;
		}
	next:
		free(fname);
		if (fd >= 0)
			close(fd);
	}

	free(cmd);
	return ret;
}

int
main (int argc, char *argv[])
{
	int opt;
	int *pids = NULL;
	unsigned int nr_pids = 0;
	unsigned int i;
	int rv = 0;

	if (argc < 2)
		usage();

	while ((opt = getopt_long(argc, argv, "f:i:o:s:",
				  pcoredump_options, NULL)) != -1)
		handle_option(opt, optarg);

	if (optind >= argc)
		usage();

	while (optind < argc) {
		long pid;

		pid = parse_numeric(argv[optind]);
		if (pid < 0)
			error(1, 0, "invalid pid %s\n", argv[optind]);

		nr_pids++;
		pids = realloc(pids, sizeof(int) * nr_pids);
		if (!pids)
			error(1, ENOMEM, "Out of memory allocatid PID array");
		pids[nr_pids - 1] = pid;
		optind++;
	}

	if (access("/proc/self/livedump", F_OK) == 0) {
		rv = proc_livedump_pids(pids, nr_pids);
	} else {
		for (i = 0; i < nr_pids; i++) {
			if (ptrace(PT_LIVEDUMP, pids[i], NULL,
				   parm_set ? &param : NULL) < 0) {
				error(0, errno, "failed to dump core of %d",
				      pids[i]);
				rv = 1;
			}
		}
	}

	free(pids);

	return rv;
}
