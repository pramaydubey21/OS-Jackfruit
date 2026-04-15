/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

static supervisor_ctx_t *g_ctx = NULL;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag, const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;
    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }
    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }
    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req, int argc,
                                char *argv[], int start_index)
{
    int i;
    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;
        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i+1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i+1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i+1], &end, 10);
            if (errno != 0 || end == argv[i+1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr, "Invalid value for --nice: %s\n", argv[i+1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "soft limit cannot exceed hard limit\n");
        return -1;
    }
    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:   return "exited";
    default:                 return "unknown";
    }
}

/* ---------------------------------------------------------------
 * Bounded Buffer
 * --------------------------------------------------------------- */
static int bounded_buffer_init(bounded_buffer_t *b)
{
    int rc;
    memset(b, 0, sizeof(*b));
    rc = pthread_mutex_init(&b->mutex, NULL);
    if (rc != 0) return rc;
    rc = pthread_cond_init(&b->not_empty, NULL);
    if (rc != 0) { pthread_mutex_destroy(&b->mutex); return rc; }
    rc = pthread_cond_init(&b->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&b->not_empty);
        pthread_mutex_destroy(&b->mutex);
        return rc;
    }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *b)
{
    pthread_cond_destroy(&b->not_full);
    pthread_cond_destroy(&b->not_empty);
    pthread_mutex_destroy(&b->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *b)
{
    pthread_mutex_lock(&b->mutex);
    b->shutting_down = 1;
    pthread_cond_broadcast(&b->not_empty);
    pthread_cond_broadcast(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
}

int bounded_buffer_push(bounded_buffer_t *b, const log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == LOG_BUFFER_CAPACITY && !b->shutting_down)
        pthread_cond_wait(&b->not_full, &b->mutex);
    if (b->shutting_down) {
        pthread_mutex_unlock(&b->mutex);
        return -1;
    }
    b->items[b->tail] = *item;
    b->tail = (b->tail + 1) % LOG_BUFFER_CAPACITY;
    b->count++;
    pthread_cond_signal(&b->not_empty);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *b, log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == 0 && !b->shutting_down)
        pthread_cond_wait(&b->not_empty, &b->mutex);
    if (b->count == 0) {
        pthread_mutex_unlock(&b->mutex);
        return -1;
    }
    *item = b->items[b->head];
    b->head = (b->head + 1) % LOG_BUFFER_CAPACITY;
    b->count--;
    pthread_cond_signal(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

/* ---------------------------------------------------------------
 * Logging Thread
 * --------------------------------------------------------------- */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    char path[PATH_MAX];
    int fd;

    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);
        fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            write(fd, item.data, item.length);
            close(fd);
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------
 * Container stdio reader thread
 * --------------------------------------------------------------- */
typedef struct {
    int read_fd;
    char container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *buffer;
} reader_args_t;

static void *container_reader_thread(void *arg)
{
    reader_args_t *r = (reader_args_t *)arg;
    log_item_t item;
    ssize_t n;

    memset(&item, 0, sizeof(item));
    strncpy(item.container_id, r->container_id, CONTAINER_ID_LEN - 1);

    while ((n = read(r->read_fd, item.data, LOG_CHUNK_SIZE)) > 0) {
        item.length = (size_t)n;
        bounded_buffer_push(r->buffer, &item);
        memset(item.data, 0, LOG_CHUNK_SIZE);
    }
    close(r->read_fd);
    free(r);
    return NULL;
}

/* ---------------------------------------------------------------
 * Child container entrypoint
 * --------------------------------------------------------------- */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;
    char proc_path[PATH_MAX];

    /* Redirect stdout and stderr to log pipe */
    dup2(cfg->log_write_fd, STDOUT_FILENO);
    dup2(cfg->log_write_fd, STDERR_FILENO);
    close(cfg->log_write_fd);

    /* Mount proc inside rootfs */
    snprintf(proc_path, sizeof(proc_path), "%s/proc", cfg->rootfs);
    mkdir(proc_path, 0555);
    if (mount("proc", proc_path, "proc", 0, NULL) != 0)
        perror("mount proc");

    /* chroot into rootfs */
    if (chroot(cfg->rootfs) != 0) {
        perror("chroot");
        return 1;
    }
    if (chdir("/") != 0) {
        perror("chdir");
        return 1;
    }

    /* Set hostname to container id */
    sethostname(cfg->id, strlen(cfg->id));

    /* Apply nice value */
    if (cfg->nice_value != 0)
        nice(cfg->nice_value);

    /* Execute the command */
    char *argv[] = { cfg->command, NULL };
    char *envp[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/root",
        NULL
    };
    execve(cfg->command, argv, envp);
    perror("execve");
    return 1;
}

/* ---------------------------------------------------------------
 * Monitor registration helpers
 * --------------------------------------------------------------- */
int register_with_monitor(int monitor_fd, const char *container_id,
                          pid_t host_pid, unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;
    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id,
                            pid_t host_pid)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;
    return 0;
}

/* ---------------------------------------------------------------
 * Launch a container
 * --------------------------------------------------------------- */
static container_record_t *launch_container(supervisor_ctx_t *ctx,
                                            const control_request_t *req)
{
    child_config_t *cfg;
    container_record_t *rec;
    char *stack;
    pid_t pid;
    int pipefd[2];
    pthread_t reader_tid;
    reader_args_t *rargs;

    /* Create log pipe */
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return NULL;
    }

    /* Build child config */
    cfg = malloc(sizeof(*cfg));
    if (!cfg) { close(pipefd[0]); close(pipefd[1]); return NULL; }
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->id, req->container_id, CONTAINER_ID_LEN - 1);
    strncpy(cfg->rootfs, req->rootfs, PATH_MAX - 1);
    strncpy(cfg->command, req->command, CHILD_COMMAND_LEN - 1);
    cfg->nice_value = req->nice_value;
    cfg->log_write_fd = pipefd[1];

    /* Allocate clone stack */
    stack = malloc(STACK_SIZE);
    if (!stack) { free(cfg); close(pipefd[0]); close(pipefd[1]); return NULL; }

    /* Clone with new namespaces */
    pid = clone(child_fn, stack + STACK_SIZE,
                CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD, cfg);

    close(pipefd[1]); /* parent closes write end */

    if (pid < 0) {
        perror("clone");
        free(stack);
        free(cfg);
        close(pipefd[0]);
        return NULL;
    }

    free(stack);

    /* Build metadata record */
    rec = malloc(sizeof(*rec));
    if (!rec) { free(cfg); close(pipefd[0]); return NULL; }
    memset(rec, 0, sizeof(*rec));
    strncpy(rec->id, req->container_id, CONTAINER_ID_LEN - 1);
    rec->host_pid = pid;
    rec->started_at = time(NULL);
    rec->state = CONTAINER_RUNNING;
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    snprintf(rec->log_path, PATH_MAX, "%s/%s.log", LOG_DIR, req->container_id);

    /* Register with kernel monitor */
    if (ctx->monitor_fd >= 0)
        register_with_monitor(ctx->monitor_fd, req->container_id, pid,
                              req->soft_limit_bytes, req->hard_limit_bytes);

    /* Start reader thread for container output */
    rargs = malloc(sizeof(*rargs));
    if (rargs) {
        rargs->read_fd = pipefd[0];
        strncpy(rargs->container_id, req->container_id, CONTAINER_ID_LEN - 1);
        rargs->buffer = &ctx->log_buffer;
        pthread_create(&reader_tid, NULL, container_reader_thread, rargs);
        pthread_detach(reader_tid);
    } else {
        close(pipefd[0]);
    }

    /* Add to metadata list */
    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    free(cfg);
    return rec;
}

/* ---------------------------------------------------------------
 * SIGCHLD handler — reap children
 * --------------------------------------------------------------- */
static void sigchld_handler(int sig)
{
    (void)sig;
    int status;
    pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (!g_ctx) continue;
        pthread_mutex_lock(&g_ctx->metadata_lock);
        container_record_t *rec = g_ctx->containers;
        while (rec) {
            if (rec->host_pid == pid) {
                if (WIFEXITED(status)) {
                    rec->state = CONTAINER_EXITED;
                    rec->exit_code = WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    rec->state = CONTAINER_KILLED;
                    rec->exit_signal = WTERMSIG(status);
                }
                break;
            }
            rec = rec->next;
        }
        pthread_mutex_unlock(&g_ctx->metadata_lock);
    }
}

static void sigterm_handler(int sig)
{
    (void)sig;
    if (g_ctx) g_ctx->should_stop = 1;
}

/* ---------------------------------------------------------------
 * Supervisor — handle one client request
 * --------------------------------------------------------------- */
static void handle_request(supervisor_ctx_t *ctx, int client_fd)
{
    control_request_t req;
    control_response_t resp;
    ssize_t n;

    memset(&resp, 0, sizeof(resp));

    n = recv(client_fd, &req, sizeof(req), 0);
    if (n <= 0) { close(client_fd); return; }

    switch (req.kind) {

    case CMD_START:
    case CMD_RUN: {
        container_record_t *rec = launch_container(ctx, &req);
        if (rec) {
            resp.status = 0;
            snprintf(resp.message, sizeof(resp.message),
                     "started container %s pid %d", rec->id, rec->host_pid);
            if (req.kind == CMD_RUN) {
                /* foreground: wait for it */
                int status;
                waitpid(rec->host_pid, &status, 0);
                pthread_mutex_lock(&ctx->metadata_lock);
                if (WIFEXITED(status)) {
                    rec->state = CONTAINER_EXITED;
                    rec->exit_code = WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    rec->state = CONTAINER_KILLED;
                    rec->exit_signal = WTERMSIG(status);
                }
                pthread_mutex_unlock(&ctx->metadata_lock);
            }
        } else {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "failed to launch container");
        }
        break;
    }

    case CMD_PS: {
        container_record_t *rec;
        char line[256];
        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message), "%-16s %-8s %-10s\n",
                 "ID", "PID", "STATE");
        pthread_mutex_lock(&ctx->metadata_lock);
        rec = ctx->containers;
        while (rec) {
            snprintf(line, sizeof(line), "%-16s %-8d %-10s\n",
                     rec->id, rec->host_pid, state_to_string(rec->state));
            strncat(resp.message, line,
                    sizeof(resp.message) - strlen(resp.message) - 1);
            rec = rec->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        break;
    }

    case CMD_LOGS: {
        char log_path[PATH_MAX];
        int fd;
        char buf[1024];
        ssize_t bytes;
        snprintf(log_path, sizeof(log_path), "%s/%s.log",
                 LOG_DIR, req.container_id);
        fd = open(log_path, O_RDONLY);
        if (fd < 0) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "no log found for %s", req.container_id);
        } else {
            resp.status = 0;
            snprintf(resp.message, sizeof(resp.message), "log: %s\n", log_path);
            send(client_fd, &resp, sizeof(resp), 0);
            while ((bytes = read(fd, buf, sizeof(buf))) > 0)
                send(client_fd, buf, bytes, 0);
            close(fd);
            close(client_fd);
            return;
        }
        break;
    }

    case CMD_STOP: {
        container_record_t *rec;
        pthread_mutex_lock(&ctx->metadata_lock);
        rec = ctx->containers;
        while (rec) {
            if (strcmp(rec->id, req.container_id) == 0) {
                kill(rec->host_pid, SIGTERM);
                rec->state = CONTAINER_STOPPED;
                resp.status = 0;
                snprintf(resp.message, sizeof(resp.message),
                         "stopped %s", rec->id);
                if (ctx->monitor_fd >= 0)
                    unregister_from_monitor(ctx->monitor_fd,
                                           rec->id, rec->host_pid);
                break;
            }
            rec = rec->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        if (resp.status != 0) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "container %s not found", req.container_id);
        }
        break;
    }

    default:
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "unknown command");
        break;
    }

    send(client_fd, &resp, sizeof(resp), 0);
    close(client_fd);
}

/* ---------------------------------------------------------------
 * Supervisor main loop
 * --------------------------------------------------------------- */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    struct sigaction sa;
    int client_fd;
    int rc;

    (void)rootfs;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;
    g_ctx = &ctx;

    /* Init metadata lock */
    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) { perror("pthread_mutex_init"); return 1; }

    /* Init bounded buffer */
    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) { perror("bounded_buffer_init"); return 1; }

    /* Create log directory */
    mkdir(LOG_DIR, 0755);

    /* Open kernel monitor */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "Warning: could not open /dev/container_monitor: %s\n",
                strerror(errno));

    /* Create UNIX domain socket */
    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(ctx.server_fd, 8) < 0) { perror("listen"); return 1; }

    /* Signal handlers */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_flags = 0;
    sa.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* Start logging thread */
    rc = pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);
    if (rc != 0) { perror("pthread_create"); return 1; }

    fprintf(stdout, "Supervisor started. Listening on %s\n", CONTROL_PATH);
    fflush(stdout);

    /* Event loop */
    while (!ctx.should_stop) {
        client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        handle_request(&ctx, client_fd);
    }

    /* Shutdown */
    fprintf(stdout, "Supervisor shutting down...\n");

    close(ctx.server_fd);
    unlink(CONTROL_PATH);

    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);
    bounded_buffer_destroy(&ctx.log_buffer);

    /* Free container records */
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *rec = ctx.containers;
    while (rec) {
        container_record_t *next = rec->next;
        free(rec);
        rec = next;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);
    pthread_mutex_destroy(&ctx.metadata_lock);

    fprintf(stdout, "Supervisor exited cleanly.\n");
    return 0;
}

/* ---------------------------------------------------------------
 * CLI client
 * --------------------------------------------------------------- */
static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Could not connect to supervisor at %s\n"
                        "Is the supervisor running?\n", CONTROL_PATH);
        close(fd);
        return 1;
    }

    send(fd, req, sizeof(*req), 0);

    /* Print any response data */
    while (recv(fd, &resp, sizeof(resp), 0) > 0) {
        printf("%s\n", resp.message);
        if (resp.status != 0) break;
    }

    close(fd);
    return 0;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr, "Usage: %s start <id> <rootfs> <command> [...]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command,      argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr, "Usage: %s run <id> <rootfs> <command> [...]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command,      argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0) return cmd_start(argc, argv);
    if (strcmp(argv[1], "run")   == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "ps")    == 0) return cmd_ps();
    if (strcmp(argv[1], "logs")  == 0) return cmd_logs(argc, argv);
    if (strcmp(argv[1], "stop")  == 0) return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
