/* launch BASE CMD ARG...: fork, execvp CMD with argv[0] CMD and stdout and
 * stderr to BASE.out and BASE.err, wait, then print one line:
 *   <rc> <maxrss KiB> <wall us> <user us> <sys us>
 * rc is the exit status, or 128 + signal. maxrss and the cpu times are
 * wait4's rusage: the peak of the child and the descendants it waited
 * for, free of the caller's own memory (bash's, or GNU time's, which this
 * replaces). built by bench-lib.sh into the trash dir */
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long us(struct timeval tv)
{
	return tv.tv_sec * 1000000L + tv.tv_usec;
}

int main(int argc, char **argv)
{
	char out[4096], err[4096];
	struct timespec a, b;
	struct rusage ru;
	int st, rc;
	pid_t pid;

	if(argc < 3) {
		fprintf(stderr, "usage: launch BASE CMD ARG...\n");
		return 2;
	}
	snprintf(out, sizeof out, "%s.out", argv[1]);
	snprintf(err, sizeof err, "%s.err", argv[1]);
	clock_gettime(CLOCK_MONOTONIC, &a);
	pid = fork();
	if(pid == 0) {
		dup2(open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600), 1);
		dup2(open(err, O_WRONLY | O_CREAT | O_TRUNC, 0600), 2);
		execvp(argv[2], argv + 2);
		_exit(127);
	}
	if(pid < 0 || wait4(pid, &st, 0, &ru) < 0) {
		perror("launch");
		return 2;
	}
	clock_gettime(CLOCK_MONOTONIC, &b);
	rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
	printf("%d %ld %lld %ld %ld\n", rc, ru.ru_maxrss,
		((b.tv_sec - a.tv_sec) * 1000000LL
			+ (b.tv_nsec - a.tv_nsec) / 1000),
		us(ru.ru_utime), us(ru.ru_stime));
	return 0;
}
