#!/usr/bin/env python3
"""
sys-call-tracer: A Linux utility to trace and log system calls in real time.
Uses ptrace to attach to processes and intercept system calls.
"""

import ctypes
import ctypes.util
import os
import sys
import struct
import signal
import argparse
import time
from datetime import datetime

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SYSCALL = 24
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETSIGINFO = 0x4202
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_EXITKILL = 0x00100000

SYS_CALL_TABLE = {
    0: "read", 1: "write", 2: "open", 3: "close",
    4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
    8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
    12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask", 15: "rt_sigreturn",
    16: "ioctl", 17: "pread64", 18: "pwrite64", 19: "readv",
    20: "writev", 21: "access", 22: "pipe", 23: "select",
    24: "sched_yield", 25: "mremap", 26: "msync", 27: "mincore",
    28: "madvise", 29: "shmget", 30: "shmat", 31: "shmctl",
    32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep",
    36: "getitimer", 37: "alarm", 38: "setitimer", 39: "getpid",
    40: "sendfile", 41: "socket", 42: "connect", 43: "accept",
    44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg",
    48: "shutdown", 49: "bind", 50: "listen", 51: "getsockname",
    52: "getpeername", 53: "socketpair", 54: "setsockopt", 55: "getsockopt",
    56: "clone", 57: "fork", 58: "vfork", 59: "execve",
    60: "exit", 61: "wait4", 62: "kill", 63: "uname",
    64: "semget", 65: "semop", 66: "semctl", 67: "shmdt",
    68: "msgget", 69: "msgsnd", 70: "msgrcv", 71: "msgctl",
    72: "fcntl", 73: "flock", 74: "fsync", 75: "fdatasync",
    76: "truncate", 77: "ftruncate", 78: "getdents", 79: "getcwd",
    80: "chdir", 81: "fchdir", 82: "rename", 83: "mkdir",
    84: "rmdir", 85: "creat", 86: "link", 87: "unlink",
    88: "symlink", 89: "readlink", 90: "chmod", 91: "fchmod",
    92: "chown", 93: "fchown", 94: "lchown", 95: "umask",
    96: "gettimeofday", 97: "getrlimit", 98: "getrusage", 99: "sysinfo",
    100: "times", 101: "ptrace", 102: "getuid", 103: "syslog",
    104: "getgid", 105: "setuid", 106: "setgid", 107: "geteuid",
    108: "getegid", 109: "setpgid", 110: "getppid", 111: "getpgrp",
    112: "setsid", 113: "setreuid", 114: "setregid", 115: "getgroups",
    116: "setgroups", 117: "setresuid", 118: "getresuid", 119: "setresgid",
    120: "getresgid", 121: "getpgid", 122: "setfsuid", 123: "setfsgid",
    124: "getsid", 125: "capget", 126: "capset", 127: "rt_sigpending",
    128: "rt_sigtimedwait", 129: "rt_sigqueueinfo", 130: "rt_sigsuspend",
    131: "sigaltstack", 132: "utime", 133: "mknod", 134: "uselib",
    135: "personality", 136: "ustat", 137: "statfs", 138: "fstatfs",
    139: "sysfs", 140: "getpriority", 141: "setpriority", 142: "sched_setparam",
    143: "sched_getparam", 144: "sched_setscheduler", 145: "sched_getscheduler",
    146: "sched_get_priority_max", 147: "sched_get_priority_min", 148: "sched_rr_get_interval",
    149: "mlock", 150: "munlock", 151: "mlockall", 152: "munlockall",
    153: "vhangup", 154: "modify_ldt", 155: "pivot_root", 156: "_sysctl",
    157: "prctl", 158: "arch_prctl", 159: "adjtimex", 160: "setrlimit",
    161: "chroot", 162: "sync", 163: "acct", 164: "settimeofday",
    165: "mount", 166: "umount2", 167: "swapon", 168: "swapoff",
    169: "reboot", 170: "sethostname", 171: "setdomainname", 172: "iopl",
    173: "ioperm", 174: "create_module", 175: "init_module",
    176: "delete_module", 177: "get_kernel_syms", 178: "query_module",
    179: "quotactl", 180: "nfsservctl", 181: "getpmsg", 182: "putpmsg",
    183: "afs_syscall", 184: "tuxcall", 185: "security", 186: "gettid",
    187: "readahead", 188: "setxattr", 189: "lsetxattr", 190: "fsetxattr",
    191: "getxattr", 192: "lgetxattr", 193: "fgetxattr", 194: "listxattr",
    195: "llistxattr", 196: "flistxattr", 197: "removexattr", 198: "lremovexattr",
    199: "fremovexattr", 200: "tkill", 201: "time", 202: "futex",
    203: "sched_setaffinity", 204: "sched_getaffinity", 205: "set_thread_area",
    206: "io_setup", 207: "io_destroy", 208: "io_getevents", 209: "io_submit",
    210: "io_cancel", 211: "get_thread_area", 212: "lookup_dcookie",
    213: "epoll_create", 214: "epoll_ctl_old", 215: "epoll_wait_old",
    216: "remap_file_pages", 217: "getdents64", 218: "set_tid_address",
    219: "restart_syscall", 220: "semtimedop", 221: "fadvise64",
    222: "timer_create", 223: "timer_settime", 224: "timer_gettime",
    225: "timer_getoverrun", 226: "timer_delete", 227: "clock_settime",
    228: "clock_gettime", 229: "clock_getres", 230: "clock_nanosleep",
    231: "exit_group", 232: "epoll_wait", 233: "epoll_ctl", 234: "tgkill",
    235: "utimes", 236: "vserver", 237: "mbind", 238: "set_mempolicy",
    239: "get_mempolicy", 240: "mq_open", 241: "mq_unlink", 242: "mq_timedsend",
    243: "mq_timedreceive", 244: "mq_notify", 245: "mq_getsetattr",
    246: "kexec_load", 247: "waitid", 248: "add_key", 249: "request_key",
    250: "keyctl", 251: "ioprio_set", 252: "ioprio_get", 253: "inotify_init",
    254: "inotify_add_watch", 255: "inotify_rm_watch", 256: "migrate_pages",
    257: "openat", 258: "mkdirat", 259: "mknodat", 260: "fchownat",
    261: "futimesat", 262: "newfstatat", 263: "unlinkat", 264: "renameat",
    265: "linkat", 266: "symlinkat", 267: "readlinkat", 268: "fchmodat",
    269: "faccessat", 270: "pselect6", 271: "ppoll", 272: "unshare",
    273: "set_robust_list", 274: "get_robust_list", 275: "splice",
    276: "tee", 277: "sync_file_range", 278: "vmsplice", 279: "move_pages",
    280: "utimensat", 281: "epoll_pwait", 282: "signalfd", 283: "timerfd_create",
    284: "eventfd", 285: "fallocate", 286: "timerfd_settime", 287: "timerfd_gettime",
    288: "accept4", 289: "signalfd4", 290: "eventfd2", 291: "epoll_create1",
    292: "dup3", 293: "pipe2", 294: "inotify_init1", 295: "preadv",
    296: "pwritev", 297: "rt_tgsigqueueinfo", 298: "perf_event_open",
    299: "recvmmsg", 300: "fanotify_init", 301: "fanotify_mark",
    302: "prlimit64", 303: "name_to_handle_at", 304: "open_by_handle_at",
    305: "clock_adjtime", 306: "syncfs", 307: "sendmmsg", 308: "setns",
    309: "getcpu", 310: "process_vm_readv", 311: "process_vm_writev",
    312: "kcmp", 313: "finit_module", 314: "sched_setattr", 315: "sched_getattr",
    316: "renameat2", 317: "seccomp", 318: "getrandom", 319: "memfd_create",
    320: "kexec_file_load", 321: "bpf", 322: "execveat", 323: "userfaultfd",
    324: "membarrier", 325: "mlock2", 326: "copy_file_range", 327: "preadv2",
    328: "pwritev2", 329: "pkey_mprotect", 330: "pkey_alloc", 331: "pkey_free",
    332: "statx", 333: "io_pgetevents", 334: "rseq", 335: "pidfd_send_signal",
    336: "io_uring_setup", 337: "io_uring_enter", 338: "io_uring_register",
    339: "open_tree", 340: "move_mount", 341: "fsopen", 342: "fsconfig",
    343: "fsmount", 344: "fspick", 345: "pidfd_open", 346: "clone3",
    347: "close_range", 348: "openat2", 349: "pidfd_getfd", 350: "faccessat2",
    351: "process_madvise", 352: "epoll_pwait2", 353: "mount_setattr",
    354: "quotactl_fd", 355: "landlock_create_ruleset", 356: "landlock_add_rule",
    357: "landlock_restrict_self", 358: "memfd_secret", 359: "process_mrelease",
    360: "futex_wait", 361: "futex_wake", 362: "futex_requeue",
    363: "futex_waitv", 364: "set_mempolicy_home_node",
}

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

class ptrace_options(ctypes.Structure):
    _fields_ = [
        ("ptrace_flags", ctypes.c_ulong),
    ]

def ptrace(request, pid, addr, data):
    libc.ptrace.errcheck = lambda result, func, args: result
    return libc.ptrace(request, pid, addr, data)

def get_regs(pid):
    regs = user_regs_struct()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
    return regs

def set_regs(pid, regs):
    ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(regs))

def wait_for_syscall(pid):
    while True:
        os.waitpid(pid, 0)
        regs = get_regs(pid)
        if regs.orig_rax in SYS_CALL_TABLE:
            return regs

def trace_child():
    ptrace(PTRACE_TRACEME, 0, 0, 0)
    os.execvp(sys.argv[1], sys.argv[1:])

def attach_to_process(pid):
    try:
        ptrace(PTRACE_ATTACH, pid, 0, 0)
        os.waitpid(pid, 0)
        options = ptrace_options()
        ptrace(129, pid, 0, ctypes.byref(options))
        return True
    except Exception as e:
        print(f"Failed to attach to process {pid}: {e}", file=sys.stderr)
        return False

def detach_process(pid):
    try:
        ptrace(PTRACE_DETACH, pid, 0, 0)
    except Exception:
        pass

def get_syscall_name(syscall_num):
    return SYS_CALL_TABLE.get(syscall_num, f"unknown_{syscall_num}")

def format_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def log_syscall(pid, syscall_num, regs, entering=True):
    syscall_name = get_syscall_name(syscall_num)
    direction = "entering" if entering else "exiting"
    timestamp = format_timestamp()
    
    if entering:
        arg1 = regs.rdi
        arg2 = regs.rsi
        arg3 = regs.rdx
        print(f"[{timestamp}] PID {pid} | {syscall_name:<20} | entering | args: {arg1}, {arg2}, {arg3}")
    else:
        ret_val = regs.rax
        print(f"[{timestamp}] PID {pid} | {syscall_name:<20} | exiting  | ret: {ret_val}")

def trace_process(pid, count=None, filter_syscalls=None):
    syscall_count = 0
    entering = True
    
    print(f"Attaching to process {pid}...")
    print(f"Press Ctrl+C to stop tracing")
    print("-" * 80)
    
    try:
        while True:
            if count and syscall_count >= count:
                break
                
            os.waitpid(pid, 0)
            regs = get_regs(pid)
            syscall_num = regs.orig_rax
            
            if syscall_num in SYS_CALL_TABLE:
                syscall_name = get_syscall_name(syscall_num)
                
                if filter_syscalls is None or syscall_name in filter_syscalls:
                    log_syscall(pid, syscall_num, regs, entering=entering)
                    syscall_count += 1
                
                entering = not entering
            
            ptrace(PTRACE_SYSCALL, pid, 0, 0)
            
    except KeyboardInterrupt:
        print(f"\nTracing interrupted. Total syscalls traced: {syscall_count}")
    except Exception as e:
        print(f"\nError during tracing: {e}", file=sys.stderr)
    finally:
        detach_process(pid)
        print(f"Detached from process {pid}")

def run_with_trace(command):
    pid = os.fork()
    if pid == 0:
        trace_child()
    else:
        os.waitpid(pid, 0)
        trace_process(pid)

def list_syscalls():
    print("Available system calls:")
    print("-" * 40)
    for num, name in sorted(SYS_CALL_TABLE.items()):
        print(f"  {num:4d} | {name}")

def main():
    parser = argparse.ArgumentParser(
        description="Trace and log system calls in real time",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p 1234              Attach to existing process
  %(prog)s -c "ls -la"          Run command with tracing
  %(prog)s -l                   List all syscalls
  %(prog)s -p 1234 -f open,read Filter specific syscalls
        """
    )
    
    parser.add_argument("-p", "--pid", type=int, help="Process ID to attach to")
    parser.add_argument("-c", "--command", help="Command to run with tracing")
    parser.add_argument("-n", "--count", type=int, help="Number of syscalls to trace")
    parser.add_argument("-f", "--filter", help="Comma-separated list of syscalls to filter")
    parser.add_argument("-l", "--list", action="store_true", help="List all available syscalls")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("Warning: Running without root privileges. Some operations may fail.", file=sys.stderr)
    
    if args.list:
        list_syscalls()
        sys.exit(0)
    
    filter_syscalls = None
    if args.filter:
        filter_syscalls = set(args.filter.split(","))
    
    if args.pid:
        trace_process(args.pid, count=args.count, filter_syscalls=filter_syscalls)
    elif args.command:
        run_with_trace(args.command.split())
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
