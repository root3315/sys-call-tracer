# sys-call-tracer

A lightweight Linux utility to trace and log system calls in real time. Built with Python and ctypes, no external dependencies needed.

## Why I Made This

Sometimes you just need to see what syscalls a process is making without the full power (and complexity) of strace. This tool gives you a clean, timestamped log of system calls with their arguments and return values.

## Quick Start

```bash
# Make it executable
chmod +x sys_call_tracer.py

# Run with sudo (ptrace needs privileges)
sudo ./sys_call_tracer.py -p <PID>

# Or trace a command from the start
sudo ./sys_call_tracer.py -c "ls -la /tmp"

# List all available syscalls
./sys_call_tracer.py -l

# List syscall categories
./sys_call_tracer.py --list-categories
```

## Usage

```
usage: sys_call_tracer.py [-h] [-p PID] [-c COMMAND] [-n COUNT] [-f FILTER] [-x EXCLUDE]
                          [-C CATEGORY] [-X EXCLUDE_CATEGORY] [-l] [--list-categories] [-v]
                          [--format {text,json}]

Trace and log system calls in real time

options:
  -h, --help            show this help message and exit
  -p PID, --pid PID     Process ID to attach to
  -c COMMAND, --command COMMAND
                        Command to run with tracing
  -n COUNT, --count COUNT
                        Number of syscalls to trace
  -f FILTER, --filter FILTER
                        Comma-separated list of syscalls to include (supports wildcards: *, ?)
  -x EXCLUDE, --exclude EXCLUDE
                        Comma-separated list of syscalls to exclude (supports wildcards: *, ?)
  -C CATEGORY, --category CATEGORY
                        Comma-separated list of categories to include
  -X EXCLUDE_CATEGORY, --exclude-category EXCLUDE_CATEGORY
                        Comma-separated list of categories to exclude
  -l, --list            List all available syscalls
  --list-categories     List available syscall categories
  -v, --verbose         Enable verbose output
  --format {text,json}  Output format (default: text)
```

## Examples

### Attach to a running process

```bash
sudo ./sys_call_tracer.py -p 1234
```

### Trace a specific command

```bash
sudo ./sys_call_tracer.py -c "cat /etc/passwd"
```

### Filter by syscall names

```bash
# Only trace open, read, write, and close
sudo ./sys_call_tracer.py -p 1234 -f open,read,write,close

# Use wildcards to match patterns
sudo ./sys_call_tracer.py -p 1234 -f "open*,read*,write*"
```

### Filter by category

```bash
# Only trace file-related syscalls
sudo ./sys_call_tracer.py -p 1234 -C file

# Trace both file and network syscalls
sudo ./sys_call_tracer.py -p 1234 -C file,network

# Trace memory operations
sudo ./sys_call_tracer.py -p 1234 -C memory
```

### Exclude specific syscalls

```bash
# Trace everything except exit calls
sudo ./sys_call_tracer.py -p 1234 -x exit,exit_group

# Exclude noisy syscalls using wildcards
sudo ./sys_call_tracer.py -p 1234 -x "fstat*,gettid"
```

### Combine include and exclude filters

```bash
# Include file syscalls but exclude stat operations
sudo ./sys_call_tracer.py -p 1234 -C file -x stat,lstat,fstat

# Include open/read but exclude openat variants
sudo ./sys_call_tracer.py -p 1234 -f open,read -x openat*
```

### Trace only the first 50 syscalls

```bash
sudo ./sys_call_tracer.py -p 1234 -n 50
```

## Output Format

### Text (default)

```
[2026-03-29 14:32:15.123] PID 1234 | open                 | entering | args: 140736214016000, 0, 0
[2026-03-29 14:32:15.124] PID 1234 | open                 | exiting  | ret: 3
[2026-03-29 14:32:15.125] PID 1234 | read                 | entering | args: 3, 140736214015488, 8192
[2026-03-29 14:32:15.126] PID 1234 | read                 | exiting  | ret: 1024
```

### JSON

Use `--format json` to output one JSON object per line:

```json
{"timestamp": "2026-03-29 14:32:15.123", "pid": 1234, "syscall": "open", "direction": "entering", "args": {"arg1": 140736214016000, "arg2": 0, "arg3": 0}}
{"timestamp": "2026-03-29 14:32:15.124", "pid": 1234, "syscall": "open", "direction": "exiting", "return_value": 3}
```

```bash
sudo ./sys_call_tracer.py -p 1234 --format json
```

Each line shows:
- Timestamp with millisecond precision
- Process ID
- System call name (padded for alignment)
- Direction (entering/exiting)
- Arguments (for entering) or return value (for exiting)

## Syscall Categories

The tracer supports filtering by these syscall categories:

| Category | Description | Example Syscalls |
|----------|-------------|------------------|
| file | File I/O operations | open, read, write, close, stat |
| network | Network/socket operations | socket, connect, bind, sendto |
| process | Process management | fork, execve, exit, wait4 |
| memory | Memory management | mmap, mprotect, munmap, brk |
| signal | Signal handling | rt_sigaction, kill, pause |
| time | Time-related calls | gettimeofday, clock_gettime |
| ipc | Inter-process communication | semget, shmget, msgget, futex |
| info | System information | uname, sysinfo, getrlimit |

Use `--list-categories` to see all categories with syscall counts.
Use `-l` to see all syscalls with their associated categories.

## How It Works

The tracer uses the `ptrace` system call to attach to a process and intercept system calls. When a traced process makes a syscall:

1. The kernel stops the process
2. We get notified via `waitpid`
3. We read the register state to see which syscall and its arguments
4. We log the info and let the process continue with `PTRACE_SYSCALL`
5. Repeat for the syscall exit

This is similar to how strace works, but with a simpler implementation focused on logging.

## Requirements

- Linux (ptrace is Linux-specific)
- Python 3.6+
- Root/sudo privileges (ptrace requires it)

No external Python packages needed - everything uses the standard library.

## Limitations

- x86_64 only (register structure is architecture-specific)
- Can be detected by anti-debugging techniques
- May not work with heavily multi-threaded programs without some race conditions
- No syscall argument decoding (shows raw values, not string paths)

## Common Syscalls

| Number | Name | Description |
|--------|------|-------------|
| 0 | read | Read from file descriptor |
| 1 | write | Write to file descriptor |
| 2 | open | Open a file |
| 3 | close | Close file descriptor |
| 42 | connect | Connect to socket |
| 59 | execve | Execute program |
| 257 | openat | Open file relative to directory |

Run with `-l` to see the full list of 365 supported syscalls.

## Debugging Tips

If tracing fails:

1. Make sure you're running as root
2. Check if the target process is still running
3. Some processes may use `PR_SET_DUMPABLE` to prevent tracing
4. Containers and namespaces can complicate things

## License

MIT - do whatever you want with it.

## Contributing

Found a bug? Want to add argument decoding or JSON output? Feel free to fork and hack on it.
