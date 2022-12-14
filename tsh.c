/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * a tiny shell program which support:
 * 1. full path process execution
 * 2. input & output redirect
 * 3. signal processing, including
 *    3.1 Ctrl + C SIGINT
 *    3.2 Ctrl + Z SIGTSTP
 *    3.3 SIGCHILD
 * 4. child process reaping(by sigchld triggered in parent process)
 *
 * use signal as asynchronous communication between parent process and child
 * process
 *
 * @author Xuan Peng <xuanepeng@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif
#define BUFLEN = 100;

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);
void waitfg(pid_t pid);
void process_bg(char **argv);
void process_fg(char **argv);
extern char **environ;
/**
 * @brief the main function of the tiny shell program. Below functionality are
 included:
 1. stderr redirect
 2. commandline parsing
 3. init job list
 4. install initial signal handler
 5. an infinite loop to process user's command, terminated when receive certain
 signals
 *
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief parse a user-given command line and execute it.
 * @param cmdline: the user-given command line
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    sigset_t mask_all, mask_child, old_all;
    pid_t pid;
    int infd = -1, outfd = -1;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    if (token.infile != NULL) {
        infd = open(token.infile, O_RDONLY, ((DEF_MODE) & (~DEF_UMASK)));
        if (infd < 0) {
            if (errno == ENOENT) {
                sio_eprintf("%s: No such file or directory\n", token.infile);
            } else {
                sio_eprintf("%s: Permission denied\n", token.infile);
            }
            return;
        }
    }

    if (token.outfile != NULL) {
        outfd = open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC, DEF_MODE);
        if (outfd < 0) {
            sio_eprintf("%s: Permission denied\n", token.outfile);
            return;
        }
    }
    // if current command is a built in command
    if (token.builtin != BUILTIN_NONE) {
        switch (token.builtin) {
        case BUILTIN_QUIT: {
            exit(0);
            break;
        }
        case BUILTIN_JOBS: {
            // output redirect
            int tmpfd = dup(STDOUT_FILENO);
            if (outfd >= 0) {
                dup2(outfd, STDOUT_FILENO);
            }
            // every time manipulate job_list, all signal must be ignored.
            sigfillset(&mask_all);
            sigprocmask(SIG_BLOCK, &mask_all, &old_all);
            list_jobs(STDOUT_FILENO);
            sigprocmask(SIG_SETMASK, &old_all, NULL);
            if (outfd >= 0) { // restore redirect
                dup2(tmpfd, STDOUT_FILENO);
            }
            break;
        }
        case BUILTIN_BG: {
            process_bg(token.argv);
            break;
        }
        case BUILTIN_FG: {
            process_fg(token.argv);
            break;
        }
        case BUILTIN_NONE: {
            sio_printf("enter builtin_none, should never be triggered\n");
            // Never be triggered. Just to pass compiling check
            break;
        }
        }
    }
    // if current command is not a built in command
    else {
        sigemptyset(&mask_child);
        sigaddset(&mask_child, SIGCHLD);
        // block all signal to prevent race condition
        sigfillset(&mask_all);
        sigprocmask(SIG_BLOCK, &mask_all, &old_all);

        // 1. do fork to create the child process
        if (!(pid = fork())) {
            if (infd >= 0) {
                dup2(infd, STDIN_FILENO);
            }
            if (outfd >= 0) {
                dup2(outfd, STDOUT_FILENO);
            }
            // restore the sig mask for child process
            sigprocmask(SIG_SETMASK, &old_all, NULL);
            // make the child process in an independent process group
            if (setpgid(0, 0) < 0) {
                sio_eprintf("error happens when setpgid\n");
                return;
            }
            // child process enter execve and will never return
            if (execve(token.argv[0], token.argv, environ) < 0) {
                if (errno == EACCES) {
                    sio_eprintf("%s: Permission denied\n", token.argv[0]);
                } else {
                    sio_eprintf("%s: No such file or directory\n",
                                token.argv[0]);
                }
                exit(1);
            }
        }
        // 2. if the command is a fg command, wait till return
        if (parse_result == PARSELINE_FG) {
            // ingore all singals
            // sigprocmask(SIG_BLOCK, &mask_all, NULL);
            add_job(pid, FG, cmdline);
            waitfg(pid);
            sigprocmask(SIG_SETMASK, &old_all, NULL);
        }
        // 3. if the command is a bg command. Print its info
        else {
            // sigprocmask(SIG_BLOCK, &mask_all, NULL);
            add_job(pid, BG, cmdline);
            int job = job_from_pid(pid);
            sio_printf("[%d] (%d) %s\n", job, pid, cmdline);
            sigprocmask(SIG_SETMASK, &old_all, NULL);
        }
    }
    if (infd >= 0) {
        close(infd);
    }
    if (outfd >= 0) {
        close(outfd);
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief handler for terminated or stopped child (upon child process receiving
 * a sigint or sigtstp)
 *
 * 1. if the child process is terminated, then delete the child process from job
 * list
 * 2. if the child process is stopped, then change its state to Stopped
 */
void sigchld_handler(int sig) {
    pid_t pid;
    int prev_errno = errno;
    int stat_loc;

    /*
    / use a while loop instead of a single if.
    / since multiple signal may have received but the sigchld bit
    / would only be 1, not more
    / so we need to check through all possible child processes
    */
    while ((pid = waitpid(-1, &stat_loc, WNOHANG | WUNTRACED)) > 0) {
        sigset_t mask_all;
        sigfillset(&mask_all);
        sigset_t prev_mask;

        sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
        jid_t jid = job_from_pid(pid);

        /*
        / when a child process exited naturally.
        / delete it from our job list
        */
        if (WIFEXITED(stat_loc)) {
            delete_job(jid);
        }
        /*
         when a child is terminated by a Ctrl-C
         */
        else if (WIFSIGNALED(stat_loc)) {
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(stat_loc));
            delete_job(jid);
        }
        /*
        if the child is stopped by a Ctrl-z
        */
        else if (WIFSTOPPED(stat_loc)) {
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(stat_loc));
            job_set_state(jid, ST);
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }
    errno = prev_errno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}

/**
 * @brief wait for a foreground child process to exit
 * @param pid: the pid of the foreground process
 */
void waitfg(pid_t pid) {
    int prev_errno = errno;
    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    while (fg_job() > 0) {
        sigsuspend(&empty_mask);
    }
    errno = prev_errno;
    return;
}

/**
 * @brief process the built-in bg command
 * @param pid: the pid of the foreground process
 */
void process_bg(char **argv) {
    if (argv[0] == NULL || argv[1] == NULL) {
        sio_eprintf("bg: argument must be a PID or %%jobid\n");
        sio_eprintf("bg command requires PID or %%jobid argument\n");
        return;
    }

    int prev_errno = errno;
    int id;
    int pid;
    int jid;
    sigset_t mask_all, mask_prev;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
    // if this is a jid
    if (argv[1][0] == '%') {
        id = atoi(&argv[1][1]);
        if (!job_exists(id)) {
            sio_eprintf("%%%d: No such job\n", id);
            sigprocmask(SIG_SETMASK, &mask_prev, NULL);
            return;
        }
        pid = job_get_pid(id);
        jid = id;
    }
    // if this is a pid
    else {
        id = atoi(&argv[1][0]);
        if (!job_exists(job_from_pid(id))) {
            sigprocmask(SIG_SETMASK, &mask_prev, NULL);
            return;
        }
        pid = id;
        jid = job_from_pid(id);
    }

    // send a SIGCONT singal if the given job is a stopped job
    if (job_get_state(jid) == ST) {
        job_set_state(jid, BG);
        kill(-pid, SIGCONT);
        sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
    }

    sigprocmask(SIG_SETMASK, &mask_prev, NULL);
    errno = prev_errno;
}

/**
 * @brief process the built-in fg command
 * @param pid: the pid of the foreground process
 */
void process_fg(char **argv) {
    if (argv[0] == NULL || argv[1] == NULL) {
        sio_eprintf("fg: argument must be a PID or %%jobid\n");
        sio_eprintf("fg command requires PID or %%jobid argument\n");
        return;
    }

    int prev_errno = errno;
    int id;
    int pid;
    int jid;
    sigset_t mask_all, mask_prev;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
    // if this is a jid
    if (argv[1][0] == '%') {
        id = atoi(&argv[1][1]);
        if (!job_exists(id)) {
            sio_eprintf("%%%d: No such job\n", id);
            sigprocmask(SIG_SETMASK, &mask_prev, NULL);
            errno = prev_errno;
            return;
        }
        pid = job_get_pid(id);
        jid = id;
    }
    // if this is a pid
    else {
        id = atoi(&argv[1][0]);
        if (!job_exists(job_from_pid(id))) {
            sigprocmask(SIG_SETMASK, &mask_prev, NULL);
            errno = prev_errno;
            return;
        }
        pid = id;
        jid = job_from_pid(id);
    }

    // send a SIGCONT singal
    job_set_state(jid, FG);
    kill(-pid, SIGCONT);
    waitfg(pid);

    sigprocmask(SIG_SETMASK, &mask_prev, NULL);
    errno = prev_errno;
}

/**
 * @brief the handler for sigint (ctrl + c)
 * Parent process don't need to handle this!
 */
void sigint_handler(int sig) {
    int prev_errno = errno;
    sigset_t mask_all, prev_mask;
    sigfillset(&mask_all);

    sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
    jid_t jid = fg_job();

    if (jid != 0) {
        pid_t pid = job_get_pid(jid);
        kill(-pid, SIGINT);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        errno = prev_errno;
        return;
    }

    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = prev_errno;
}

/**
 * @brief handle a sigtstp signal.
 * Parent process don't need to handle this!
 */
void sigtstp_handler(int sig) {
    int prev_errno = errno;
    sigset_t mask_all, prev_mask;
    sigfillset(&mask_all);

    sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
    jid_t jid = fg_job();

    if (jid != 0) {
        pid_t pid = job_get_pid(jid);
        kill(-pid, SIGTSTP);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        errno = prev_errno;
        return;
    }

    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = prev_errno;
}