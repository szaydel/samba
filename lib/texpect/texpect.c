/*
 * Copyright (c) 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "replace.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "lib/util/sys_rw.h"

#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#ifdef HAVE_BSD_LIBUTIL_H
#include <bsd/libutil.h>
#elif defined HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifdef	STREAMSPTY
#include <stropts.h>
#endif /* STREAMPTY */

#include <popt.h>

#ifdef HAVE_ERR_H
#include <err.h>
#else
const char progname[] = "unknown program";

static void err(int eval, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 0);
static void errx(int eval, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 0);

static void err(int eval, const char *fmt, ...)
{
	int err_errno = errno;
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(err_errno));
	exit(eval);
}

static void errx(int eval, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(eval);
}

#endif

struct command {
	enum { CMD_EXPECT = 0, CMD_SEND, CMD_PASSWORD } type;
	unsigned int lineno;
	char *str;
	struct command *next;
};

/*
 *
 */

static struct command *commands, **next = &commands;

static sig_atomic_t alarmset = 0;

static int opt_timeout = 10;
static int opt_verbose;

static int master;
static int slave;
static char line[256] = { 0 };

static void caught_signal(int signo)
{
	alarmset = signo;
}


static void open_pty(void)
{
#ifdef _AIX
	printf("implement open_pty\n");
	exit(77);
#endif
#if defined(HAVE_OPENPTY) || defined(__linux) || defined(__osf__) /* XXX */
	if(openpty(&master, &slave, line, 0, 0) == 0)
		return;
#endif /* HAVE_OPENPTY .... */
#ifdef STREAMSPTY
	{
		char *clone[] = {
			"/dev/ptc",
			"/dev/ptmx",
			"/dev/ptm",
			"/dev/ptym/clone",
			NULL
		};
		char **q;

		for(q = clone; *q; q++){
			master = open(*q, O_RDWR);
			if(master >= 0){
#ifdef HAVE_GRANTPT
				grantpt(master);
#endif
#ifdef HAVE_UNLOCKPT
				unlockpt(master);
#endif
				strlcpy(line, ptsname(master), sizeof(line));
				slave = open(line, O_RDWR);
				if (slave < 0)
					errx(1, "failed to open slave when using %s", *q);
				ioctl(slave, I_PUSH, "ptem");
				ioctl(slave, I_PUSH, "ldterm");

				return;
			}
		}
	}
#endif /* STREAMSPTY */

	/* more cases, like open /dev/ptmx, etc */

	exit(77);
}

/*
 *
 */

static char *iscmd(const char *buf, const char *s)
{
	size_t len = strlen(s);

	if (strncmp(buf, s, len) != 0) {
		return NULL;
	}

	return strdup(buf + len);
}

static void parse_configuration(const char *fn)
{
	struct command *c;
	char *conf_line = NULL;
	char *str;
	size_t len = 0;
	unsigned int lineno = 0;
	FILE *cmd;
	const char *err_message = NULL;
	char err_buf[256];

	cmd = fopen(fn, "r");
	if (cmd == NULL)
		err(1, "open: %s", fn);

	while (getline(&conf_line, &len, cmd) != -1) {
		lineno++;

		conf_line[strcspn(conf_line, "#\n")] = '\0';
		if (conf_line[0] == '\0') {
			continue;
		}

		c = calloc(1, sizeof(*c));
		if (c == NULL) {
			err_message = "calloc failed";
			goto out;
		}

		c->lineno = lineno;

		if ((str = iscmd(conf_line, "expect ")) != NULL) {
			c->type = CMD_EXPECT;
		} else if ((str = iscmd(conf_line, "send ")) != NULL) {
			c->type = CMD_SEND;
		} else if ((str = iscmd(conf_line, "password ")) != NULL) {
			c->type = CMD_PASSWORD;
		} else {
			free(c);
			snprintf(err_buf,
				 sizeof(err_buf),
				 "Invalid command on line %d: %s",
				 lineno,
				 conf_line);
			err_message = err_buf;
			goto out;
		}

		c->str = str;

		(*next) = c;
		next = &(c->next);
	}
out:
	free(conf_line);
	fclose(cmd);
	if (err_message) {
		errx(1, "%s", err_message);
	}
}

/*
 *
 */

static int eval_parent(pid_t pid)
{
	struct command *c;
	char in;
	size_t len = 0;
	ssize_t sret;

	for (c = commands; c != NULL; c = c->next) {
		switch(c->type) {
		case CMD_EXPECT:
			if (opt_verbose) {
				printf("[expecting %s]\n", c->str);
			}
			len = 0;
			alarm(opt_timeout);
			while((sret = read(master, &in, sizeof(in))) > 0) {
				alarm(opt_timeout);
				printf("%c", in);
				if (c->str[len] != in) {
					len = 0;
					continue;
				}
				len++;
				if (c->str[len] == '\0') {
					break;
				}
			}
			alarm(0);
			if (alarmset == SIGALRM) {
				errx(1, "timeout waiting for %s (line %u)",
						c->str, c->lineno);
			} else if (alarmset) {
				errx(1, "got a signal %d waiting for %s (line %u)",
						(int)alarmset, c->str, c->lineno);
			}

			if (sret <= 0) {
				errx(1, "end command while waiting for %s (line %u)",
						c->str, c->lineno);
			}
			break;
		case CMD_SEND:
		case CMD_PASSWORD: {
			size_t i = 0;
			const char *msg = (c->type == CMD_PASSWORD) ? "****" : c->str;

			if (opt_verbose) {
				printf("[send %s]\n", msg);
			}

			len = strlen(c->str);

			while (i < len) {
				if (c->str[i] == '\\' && i < len - 1) {
					char ctrl;
					i++;
					switch(c->str[i]) {
					case 'n':
						ctrl = '\n';
						break;
					case 'r':
						ctrl = '\r';
						break;
					case 't':
						ctrl = '\t';
						break;
					default:
						errx(1,
						     "unknown control char %c (line %u)",
						     c->str[i],
						     c->lineno);
					}
					if (sys_write(master, &ctrl, 1) != 1) {
						errx(1, "command refused input (line %u)", c->lineno);
					}
				} else {
					if (sys_write(master, &c->str[i], 1) != 1) {
						errx(1, "command refused input (line %u)", c->lineno);
					}
				}
				i++;
			}
			break;
		}
		default:
			abort();
		}
	}

	while(read(master, &in, sizeof(in)) > 0) {
		printf("%c", in);
	}

	if (opt_verbose) {
		printf("[end of program]\n");
	}

	/*
	 * Fetch status from child
	 */
	{
		int ret, status;

		ret = waitpid(pid, &status, 0);
		if (ret == -1) {
			err(1, "waitpid");
		}

		if (WIFEXITED(status) && WEXITSTATUS(status)) {
			return WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			printf("killed by signal: %d\n", WTERMSIG(status));
			return 1;
		}
	}

	return 0;
}

/*
 *
 */
struct poptOption long_options[] = {
	POPT_AUTOHELP
	{
		.longName  = "timeout",
		.shortName = 't',
		.argInfo   = POPT_ARG_INT,
		.arg       = &opt_timeout,
		.val       = 't',
	},
	{
		.longName  = "verbose",
		.shortName = 'v',
		.argInfo   = POPT_ARG_NONE,
		.arg       = &opt_verbose,
		.val       = 'v',
	},
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	int optidx = 0;
	pid_t pid;
	poptContext pc = NULL;
	const char *instruction_file;
	const char **args;
	const char *program;
	char * const *program_args;

	pc = poptGetContext("texpect",
			    argc,
			    argv,
			    long_options,
			    POPT_CONTEXT_POSIXMEHARDER);

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		goto out;
	}

	while ((optidx = poptGetNextOpt(pc)) != -1) {
		switch (optidx) {
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(optidx));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	instruction_file = poptGetArg(pc);
	args = poptGetArgs(pc);
	if (args == NULL) {
		poptPrintHelp(pc, stderr, 0);
		goto out;
	}

	program_args = (char * const *)discard_const_p(char *, args);
	program = program_args[0];

	if (opt_verbose) {
		int i;

		printf("Using instruction_file: %s\n", instruction_file);
		printf("Executing '%s' ", program);
		for (i = 0; program_args[i] != NULL; i++) {
			printf("'%s' ", program_args[i]);
		}
		printf("\n");
	}

	parse_configuration(instruction_file);

	open_pty();

	pid = fork();
	switch (pid) {
		case -1:
			err(1, "Failed to fork");

			/* Never reached */
			goto out;
		case 0:

			if(setsid()<0)
				err(1, "setsid");

			dup2(slave, STDIN_FILENO);
			dup2(slave, STDOUT_FILENO);
			dup2(slave, STDERR_FILENO);

			closefrom(STDERR_FILENO + 1);

			/* texpect <expect_instructions> <progname> [<args>] */
			execvp(program, program_args);
			err(1, "Failed to exec: %s", program);

			/* Never reached */
			goto out;
		default:
			close(slave);
			{
				struct sigaction sa;

				sa.sa_handler = caught_signal;
				sa.sa_flags = 0;
				sigemptyset (&sa.sa_mask);

				sigaction(SIGALRM, &sa, NULL);
			}

			poptFreeContext(pc);
			return eval_parent(pid);
	}

	/* Never reached */

out:
	poptFreeContext(pc);
	return 1;
}
