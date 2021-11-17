/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
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

char *envp[] = {NULL};

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

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    // TODO: Implement commands here.
    // if current command is a built in command
    if (token.builtin != BUILTIN_NONE) {
        switch (token.builtin) {
        case BUILTIN_QUIT:
            exit(0);
            break;
        case BUILTIN_JOBS:
            list_jobs(STDOUT_FILENO);
            break;
        case BUILTIN_BG:
            process_bg(token.argv);
            break;
        case BUILTIN_FG:
            process_fg(token.argv);
            break;
        case BUILTIN_NONE:
            // Never be triggered. Just to pass compiling check
            break;
        }
    }
    // if current command is not a built in command
    else {
        sigfillset(&mask_all);
        sigemptyset(&mask_child);
        sigaddset(&mask_child, SIGCHLD);
        // block SIGCHILD in the child process to prevent race condition
        sigprocmask(SIG_BLOCK, &mask_child, &old_all);

        // 1. do fork to create the child process
        if ((pid = fork()) == 0) {
            // restore the sig mask for child process
            sigprocmask(SIG_SETMASK, &old_all, NULL);
            // make the child process in an independent process group
            setpgid(0, 0);
            execve(token.argv[0], token.argv, envp);
        }

        // 2. if the command is a fg command, wait till return
        if (parse_result == PARSELINE_FG) {
            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            add_job(pid, FG, cmdline);
            sigprocmask(SIG_SETMASK, &old_all, NULL);

            waitfg(pid);
        }
        // 3. if the command is a bg command. Print its info
        else {
            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            add_job(pid, BG, cmdline);
            sigprocmask(SIG_SETMASK, &old_all, NULL);

            int job = job_from_pid(pid);
            printf("[%d] (%d) %s", job, pid, cmdline);
        }
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief <What does sigchld_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigchld_handler(int sig) {}

/**
 * @brief the handler for sigint (ctrl + c)
 */
void sigint_handler(int sig) {
    pid_t pid = job_get_pid(fg_job());
    int prev_errno = errno;

    if (pid <= 0)
        return;

    kill(-pid, SIGINT);
    errno = prev_errno;
    return;
}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigtstp_handler(int sig) {
    pid_t pid = job_get_pid(fg_job());
    int prev_errno = errno;

    if (pid <= 0)
        return;

    kill(-pid, SIGTSTP);
    errno = prev_errno;
    return;
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
    sigset_t mask;
    sigemptyset(&mask);

    while (pid == job_get_pid(fg_job())) {
        sigsuspend(&mask);
    }
    return;
}

/**
 * @brief process the built-in bg command
 * @param pid: the pid of the foreground process
 */
void process_bg(char **argv) {
    // TODO
}

/**
 * @brief process the built-in fg command
 * @param pid: the pid of the foreground process
 */
void process_fg(char **argv) {
    // TODO
}