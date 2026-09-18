#ifndef KOS_UAPI_SYSCALL_NUMBERS_H
#define KOS_UAPI_SYSCALL_NUMBERS_H

/* Standard POSIX-aligned Syscall Numbers for KOS */
#define SYS_exit        1
#define SYS_fork        2
#define SYS_read        3
#define SYS_write       4
#define SYS_open        5
#define SYS_close       6
#define SYS_waitpid     7
#define SYS_execve      8
#define SYS_stat        9
#define SYS_fstat       10
#define SYS_lseek       11
#define SYS_mmap        12
#define SYS_munmap      13
#define SYS_mprotect    14
#define SYS_getpid      15
#define SYS_getppid     16
#define SYS_yield       17
#define SYS_sleep       18
#define SYS_socket      20
#define SYS_connect     21
#define SYS_accept      22
#define SYS_sendto      23
#define SYS_recvfrom    24
#define SYS_bind        25
#define SYS_listen      26
#define SYS_poll        27
#define SYS_gettime     30
#define SYS_sysinfo     31

#define KOS_MAX_SYSCALL_NR 64

/* Standard POSIX Negative Error Codes */
#define EPERM           1   /* Operation not permitted */
#define ENOENT          2   /* No such file or directory */
#define ESRCH           3   /* No such process */
#define EINTR           4   /* Interrupted system call */
#define EIO             5   /* I/O error */
#define ENXIO           6   /* No such device or address */
#define E2BIG           7   /* Argument list too long */
#define ENOEXEC         8   /* Exec format error */
#define EBADF           9   /* Bad file descriptor */
#define ECHILD          10  /* No child processes */
#define EAGAIN          11  /* Resource temporarily unavailable */
#define ENOMEM          12  /* Out of memory */
#define EACCES          13  /* Permission denied */
#define EFAULT          14  /* Bad address */
#define EBUSY           16  /* Device or resource busy */
#define EEXIST          17  /* File exists */
#define ENODEV          19  /* No such device */
#define ENOTDIR         20  /* Not a directory */
#define EISDIR          21  /* Is a directory */
#define EINVAL          22  /* Invalid argument */
#define ENFILE          23  /* File table overflow */
#define EMFILE          24  /* Too many open files */
#define ENOSPC          28  /* No space left on device */
#define ESPIPE          29  /* Illegal seek */
#define EPIPE           32  /* Broken pipe */
#define ENOSYS          38  /* Function not implemented */
#define ENOTEMPTY       39  /* Directory not empty */
#define ETIMEDOUT       110 /* Connection timed out */
#define ECONNREFUSED    111 /* Connection refused */

#endif /* KOS_UAPI_SYSCALL_NUMBERS_H */
