/*
 * Copyright 2026 SilicaProxy Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * scanner-exec: runs one external scanner (GuardDog, malcontent) under the unprivileged uid of its
 * job, never under the uid of the service (appuser), which holds the database password and the API
 * keys in its environment and can read and write every job's directory.
 *
 *   cd <job directory> && scanner-exec <tool> [arguments...]
 *
 * Who runs as whom: the Java service gives each job in flight one id of a pool (FIRST_ID ..
 * FIRST_ID + SLOTS - 1, one user and one group per id, created by the Dockerfile). It hands the job
 * directory to that group (rwxr-x---: the scanner reads the artifacts, cannot write beside them) and
 * its home/ subdirectory (rwxrwx---: HOME and TMPDIR of the scanner), and starts this launcher in the
 * job directory. The launcher takes the id from the group of its working directory, so it can only
 * switch to an id the service handed a directory to, and the scanner of one job can neither read
 * nor alter another job's directory (different id, nothing open to others).
 *
 * Privilege: this file is the only one in the image with capabilities, and only CAP_SETUID and
 * CAP_SETGID (setcap cap_setuid,cap_setgid=ep), executable only by appgroup (root:appgroup 0750).
 * It is never setuid root, never runs code from its caller other than the tool it execs once all
 * privileges are gone, and only ever switches to an id of the pool. The container keeps only these
 * two capabilities in its bounding set (cap_drop: ALL in docker/compose.yaml); no-new-privileges
 * cannot be set on the container, since it would stop the kernel from granting them here, so this
 * launcher sets it on the scanner itself instead.
 *
 * The tool runs as uid = gid = the job id, with the shared "scanner" group as only supplementary
 * group (GuardDog's popular-packages cache), no capability, no_new_privs and the parent-death
 * signal. Since the service can no longer signal it, the launcher stays as its parent: when the
 * tool exits or the service asks it to stop (SIGTERM, on a timeout), it kills every process of the
 * job id -- including any the tool daemonized -- then makes the directories the tool created under
 * home/ group-writable, so that the service can delete them. It exits with the tool's status.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(FIRST_ID) || !defined(SLOTS) || !defined(SHARED_GID)
#error "build with -DFIRST_ID=<first job id> -DSLOTS=<number of ids> -DSHARED_GID=<gid of the scanner group>"
#endif

#define HOME_DIRECTORY "home"
#define MAX_DEPTH 128
#define FAILURE 126

static void die(const char *what) {
    fprintf(stderr, "scanner-exec: %s: %s\n", what, strerror(errno));
    _exit(FAILURE);
}

static void refuse(const char *why) {
    fprintf(stderr, "scanner-exec: %s\n", why);
    _exit(FAILURE);
}

/* The job id: the group the service handed the working directory to. Only the owner of the
   directory (the caller) can have set it. */
static uid_t job_id(void) {
    struct stat st;
    if (stat(".", &st) != 0) {
        die("stat of the working directory");
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
        refuse("the working directory does not belong to the caller");
    }
    if (st.st_gid < FIRST_ID || st.st_gid >= FIRST_ID + SLOTS) {
        refuse("the working directory is not handed to a scanner group");
    }
    if ((st.st_mode & (S_IWGRP | S_IRWXO)) != 0) {
        refuse("the working directory is writable by the scanner or open to others");
    }
    return (uid_t) st.st_gid;
}

/* Becomes the job id for good: ids, groups, capabilities (none left, none to regain). */
static void drop_to(uid_t id) {
    gid_t groups[] = { SHARED_GID };
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    uid_t caller = getuid();

    memset(data, 0, sizeof data);
    if (setgroups(1, groups) != 0) {
        die("setgroups");
    }
    if (setresgid(id, id, id) != 0) {
        die("setresgid");
    }
    if (setresuid(id, id, id) != 0) {
        die("setresuid");
    }
    /* Between two non-root uids the kernel keeps the capabilities: clear them explicitly. */
    if (syscall(SYS_capset, &header, data) != 0) {
        die("capset");
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL) {
        die("clearing the ambient capabilities");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        die("no_new_privs");
    }
    if (setuid(caller) == 0 || setuid(0) == 0 || setgid(0) == 0
            || getuid() != id || geteuid() != id || getgid() != id || getegid() != id) {
        refuse("privileges were not dropped");
    }
}

/* Gives the group (the service) rwx on every directory the job id created below dirfd, without
   following symbolic links. Files need nothing: deleting one only takes rights on its directory. */
static void unlock(int dirfd, int depth) {
    DIR *dir = fdopendir(dirfd);
    struct dirent *entry;
    if (dir == NULL) {
        close(dirfd);
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        int child;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0
                || fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0
                || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
            continue;
        }
        if (fchmodat(dirfd, entry->d_name, (st.st_mode & 07777) | S_IRWXU | S_IRWXG, 0) != 0) {
            /* best effort: the service logs whatever it then fails to delete */
        }
        if (depth < MAX_DEPTH) {
            child = openat(dirfd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child >= 0) {
                unlock(child, depth + 1);
            }
        }
    }
    closedir(dir);
}

/* Kills every process of the job id (the tool, its children, whatever it daemonized), then unlocks
   what it left under home/. Runs in a child of the launcher that has become the job id. */
static void reap(uid_t id, const char *home) {
    int status;
    pid_t reaper = fork();
    if (reaper < 0) {
        die("fork");
    }
    if (reaper == 0) {
        int fd;
        drop_to(id);
        /* Every process this uid may signal, except this one: atomic with respect to fork. */
        kill(-1, SIGKILL);
        fd = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            unlock(fd, 0);
        }
        _exit(0);
    }
    while (waitpid(reaper, &status, 0) < 0) {
        if (errno != EINTR) {
            die("waitpid");
        }
    }
}

int main(int argc, char **argv) {
    char cwd[PATH_MAX];
    char home[PATH_MAX + sizeof HOME_DIRECTORY + 1];
    sigset_t handled;
    sigset_t previous;
    pid_t parent = getpid();
    pid_t tool;
    int status = 0;
    uid_t id;

    if (argc < 2) {
        refuse("usage: scanner-exec <tool> [arguments...]");
    }
    id = job_id();
    if (getcwd(cwd, sizeof cwd) == NULL) {
        die("getcwd");
    }
    snprintf(home, sizeof home, "%s/%s", cwd, HOME_DIRECTORY);

    /* Blocked before the fork, waited for with sigwaitinfo: no signal can be missed. */
    sigemptyset(&handled);
    sigaddset(&handled, SIGCHLD);
    sigaddset(&handled, SIGTERM);
    sigaddset(&handled, SIGINT);
    sigaddset(&handled, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &handled, &previous) != 0) {
        die("sigprocmask");
    }

    tool = fork();
    if (tool < 0) {
        die("fork");
    }
    if (tool == 0) {
        drop_to(id);
        /* Leftovers of an earlier job of this id, should its launcher have been killed. */
        kill(-1, SIGKILL);
        /* Set after the uid change, which clears it: the tool dies if the launcher is killed. */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 || getppid() != parent) {
            refuse("the launcher is gone");
        }
        if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0) {
            die("sigprocmask");
        }
        umask(007);
        /* glibc ran this launcher in secure mode (file capabilities) and dropped TMPDIR from the
           environment: set it back, otherwise the tools fall back to /tmp, which they may not write. */
        if (setenv("HOME", home, 1) != 0 || setenv("TMPDIR", home, 1) != 0) {
            die("setenv");
        }
        execvp(argv[1], argv + 1);
        die(argv[1]);
    }

    for (;;) {
        siginfo_t info;
        int sig = sigwaitinfo(&handled, &info);
        if (sig < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("sigwaitinfo");
        }
        if (sig == SIGCHLD) {
            if (waitpid(tool, &status, WNOHANG) == tool) {
                break;
            }
            continue;
        }
        /* Asked to stop (timeout of the service): kill the job's processes, collect the tool. */
        reap(id, home);
        while (waitpid(tool, &status, 0) < 0 && errno == EINTR) {
            continue;
        }
        return 128 + sig;
    }
    reap(id, home);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
