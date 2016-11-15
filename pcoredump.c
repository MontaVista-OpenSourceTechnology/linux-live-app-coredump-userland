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
#include <sys/resource.h>
#include <sys/ptrace.h>

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

  val = strtol (arg, &p, 10);
  if (val == LONG_MAX)
    error (1, 0, "invalid number '%s'", arg);
  else if (*p || errno)
    error (1, errno, "not a number '%s'", arg);
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

int
main (int argc, char *argv[])
{
  int opt, changed;
  long val;
  struct livedump_param param = {0, 0, 0, 0};
  struct option pcoredump_options[] =
    {
      {"force-limit", required_argument, 0, 'f'},
      {"io-priority", required_argument, 0, 'i'},
      {"oom-adjustment", required_argument, 0, 'o'},
      {"sched-nice", required_argument, 0, 's'},
      {0, 0, 0, 0}
    };

  if (argc < 2)
    usage ();
  changed = 0;

  while ((opt = getopt_long (argc, argv, "f:i:o:s:",
			     pcoredump_options, NULL)) != -1)
    {
      if (opt == 'f')
	{
	  if (!strcmp (optarg, "unlimited"))
	    param.core_limit = RLIM_INFINITY;
	  else
	    {
	      val = parse_numeric (optarg);
	      if (val < 0 || val > RLIM_INFINITY)
		error (1, 0, "invalid core file size limit %ld - must be [1:%ld]\n", 
		       val, RLIM_INFINITY);
	      param.core_limit = val;
	    }
	  changed++;
	  param.core_limit_set = true;
	}
      else if (opt == 'i')
	{
	  val = parse_numeric (optarg);
	  if (val < 0 || val > 7)
	    error (1, 0, "invalid IO priority %ld - "
		   "must be in range [0:7]", val);
	  param.io_prio = val;
	  if (val)
	    changed++;
	}
      else if (opt == 'o')
	{
	  val = parse_numeric (optarg);
	  if (val < OOM_DISABLE || val > OOM_ADJUST_MAX)
	    error (1, 0, "invalid OOM adjustment %ld - must be in range "
		   "[%d:%d]", val, OOM_DISABLE, OOM_ADJUST_MAX);
	  param.oom_adj = val;
	  if (val)
	    changed++;
	}
      else if (opt == 's')
	{
	  val = parse_numeric (optarg);
	  if (val < -20 || val > 19)
	    error (1, 0, "invalid scheduling niceness %ld - "
		   "must be in range [-20:19]", val);
	  param.sched_nice = val;
	  if (val)
	    changed++;
	}
      else
	usage ();
    }

  if (optind < argc)
    {
      while (optind < argc)
	{
	  long pid;

	  pid = parse_numeric (argv[optind]);
	  if (pid < 0)
	    error (1, 0, "invalid pid %lu\n", pid);
	  if (ptrace (PT_LIVEDUMP, pid, NULL, changed ? &param : NULL) < 0)
	    error (1, errno, "failed to dump core of %ld", pid);
	  optind++;
	}
    }
  else
    usage ();
  return 0;
}
