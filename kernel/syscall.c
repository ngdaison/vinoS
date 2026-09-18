#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kos/console.h>
#include <kos/handle.h>
#include <kos/keyboard.h>
#include <kos/log.h>
#include <kos/process.h>
#include <kos/serial.h>
#include <kos/socket.h>
#include <kos/syscall.h>
#include <kos/task.h>
#include <kos/timer.h>
#include <kos/uaccess.h>
#include <kos/vfs.h>
#include <kos/vmm.h>

uint64_t kos_syscall_dispatch_frame(struct syscall_frame *frame) {
    if (frame == NULL) {
        return (uint64_t)-EINVAL;
    }

    uint64_t nr = frame->rax;
    uint64_t arg0 = frame->rdi;
    uint64_t arg1 = frame->rsi;
    uint64_t arg2 = frame->rdx;
    uint64_t arg3 = frame->r10;
    uint64_t arg4 = frame->r8;
    uint64_t arg5 = frame->r9;

    return kos_syscall_dispatch(nr, arg0, arg1, arg2, arg3, arg4, arg5);
}

uint64_t kos_syscall_dispatch(uint64_t number, uint64_t arg0, uint64_t arg1,
                              uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;

    switch (number) {
        case SYS_exit: {
            struct process *proc = process_get_current();
            if (proc != NULL && proc->pid > 1) {
                process_exit(proc, (int)arg0);
            }
            return 0;
        }

        case SYS_getpid: {
            struct process *proc = process_get_current();
            return proc ? (uint64_t)proc->pid : 1;
        }

        case SYS_getppid: {
            struct process *proc = process_get_current();
            return proc ? (uint64_t)proc->ppid : 0;
        }

        case SYS_yield:
            task_yield();
            return 0;

        case SYS_sleep:
            task_sleep((uint32_t)arg0);
            return 0;

        case SYS_gettime:
            return timer_uptime_seconds();

        case SYS_sysinfo:
            return task_count();

        case SYS_write: {
            uint64_t uaddr = (arg2 > 0) ? arg1 : arg0;
            uint64_t len   = (arg2 > 0) ? arg2 : arg1;

            if (len == 0) return 0;
            if (len > 65536) len = 65536;

            char kbuf[256];
            uint64_t written = 0;
            while (written < len) {
                uint64_t chunk = len - written;
                if (chunk > sizeof(kbuf)) chunk = sizeof(kbuf);

                int err = copy_from_user(kbuf, (const void *)(uaddr + written), chunk);
                if (err != 0) {
                    return (uint64_t)-EFAULT;
                }

                for (uint64_t i = 0; i < chunk; ++i) {
                    serial_write_char(kbuf[i]);
                    if (console_is_initialized()) {
                        console_write_char(kbuf[i]);
                    }
                }
                written += chunk;
            }
            return written;
        }

        case SYS_read: {
            uint64_t uaddr   = (arg2 > 0) ? arg1 : arg0;
            uint64_t max_len = (arg2 > 0) ? arg2 : arg1;

            if (max_len == 0) return 0;
            if (max_len > 65536) max_len = 65536;

            if (!access_ok((const void *)uaddr, max_len)) {
                return (uint64_t)-EFAULT;
            }

            char kbuf[128];
            uint64_t read_bytes = 0;
            while (read_bytes < max_len) {
                char ch = 0;
                if (keyboard_read_char(&ch) && ch != 0) {
                    kbuf[0] = ch;
                    int err = copy_to_user((void *)(uaddr + read_bytes), kbuf, 1);
                    if (err != 0) return (uint64_t)-EFAULT;
                    read_bytes++;
                    if (ch == '\n') break;
                } else {
                    task_yield();
                }
            }
            return read_bytes;
        }

        case SYS_open: {
            char kpath[256];
            long res = strncpy_from_user(kpath, (const char *)arg0, sizeof(kpath));
            if (res < 0) return (uint64_t)-EFAULT;
            return (uint64_t)-ENOENT;
        }

        case SYS_close: {
            struct process *proc = process_get_current();
            if (proc != NULL && handle_close(proc, (handle_t)arg0)) {
                return 0;
            }
            return 0;
        }

        case SYS_socket: {
            struct socket *sock = NULL;
            int ret = kos_socket((int)arg0, (int)arg1, (int)arg2, &sock);
            if (ret != 0 || sock == NULL) {
                return (uint64_t)-EINVAL;
            }
            struct process *proc = process_get_current();
            if (proc != NULL) {
                handle_t h = handle_create(proc, sock, KOS_RIGHT_READ | KOS_RIGHT_WRITE | KOS_RIGHT_DESTROY);
                return (uint64_t)h;
            }
            return (uint64_t)sock->id;
        }

        case SYS_connect: {
            struct sockaddr kaddr;
            if (arg2 < sizeof(struct sockaddr_in)) return (uint64_t)-EINVAL;
            int err = copy_from_user(&kaddr, (const void *)arg1, sizeof(kaddr));
            if (err != 0) return (uint64_t)-EFAULT;
            struct process *proc = process_get_current();
            struct socket *sock = proc ? (struct socket *)handle_lookup(proc, (handle_t)arg0, KOS_RIGHT_WRITE) : NULL;
            if (sock == NULL) return (uint64_t)-EBADF;
            return (uint64_t)kos_connect(sock, &kaddr, (uint32_t)arg2);
        }

        case SYS_sendto: {
            uint64_t len = arg2;
            if (len > 65536) len = 65536;
            char kbuf[1024];
            if (len > sizeof(kbuf)) len = sizeof(kbuf);
            int err = copy_from_user(kbuf, (const void *)arg1, len);
            if (err != 0) return (uint64_t)-EFAULT;
            struct process *proc = process_get_current();
            struct socket *sock = proc ? (struct socket *)handle_lookup(proc, (handle_t)arg0, KOS_RIGHT_WRITE) : NULL;
            if (sock == NULL) return (uint64_t)-EBADF;
            return (uint64_t)kos_send(sock, kbuf, (size_t)len, (int)arg3);
        }

        case SYS_recvfrom: {
            uint64_t len = arg2;
            if (len > 65536) len = 65536;
            char kbuf[1024];
            if (len > sizeof(kbuf)) len = sizeof(kbuf);
            struct process *proc = process_get_current();
            struct socket *sock = proc ? (struct socket *)handle_lookup(proc, (handle_t)arg0, KOS_RIGHT_READ) : NULL;
            if (sock == NULL) return (uint64_t)-EBADF;
            int ret = kos_recv(sock, kbuf, (size_t)len, (int)arg3);
            if (ret > 0) {
                int err = copy_to_user((void *)arg1, kbuf, (size_t)ret);
                if (err != 0) return (uint64_t)-EFAULT;
            }
            return (uint64_t)ret;
        }

        default:
            return (uint64_t)-ENOSYS;
    }
}

const char *kos_syscall_name(uint64_t number) {
    switch (number) {
        case SYS_exit:     return "exit";
        case SYS_fork:     return "fork";
        case SYS_read:     return "read";
        case SYS_write:    return "write";
        case SYS_open:     return "open";
        case SYS_close:    return "close";
        case SYS_waitpid:  return "waitpid";
        case SYS_execve:   return "execve";
        case SYS_getpid:   return "getpid";
        case SYS_getppid:  return "getppid";
        case SYS_yield:    return "yield";
        case SYS_sleep:    return "sleep";
        case SYS_socket:   return "socket";
        case SYS_connect:  return "connect";
        case SYS_sendto:   return "sendto";
        case SYS_recvfrom: return "recvfrom";
        case SYS_gettime:  return "gettime";
        case SYS_sysinfo:  return "sysinfo";
        default:           return "unknown";
    }
}
