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
```

## Usage

```
usage: sys_call_tracer.py [-h] [-p PID] [-c COMMAND] [-n COUNT] [-f FILTER] [-l] [-v]

Trace and log system calls in real time

options:
  -h, --help            show this help message and exit
  -p PID, --pid PID     Process ID to attach to
  -c COMMAND, --command COMMAND
                        Command to run with tracing
  -n COUNT, --count COUNT
                        Number of syscalls to trace
  -f FILTER, --filter FILTER
                        Comma-separated list of syscalls to filter
  -l, --list            List all available syscalls
  -v, --verbose         Enable verbose output
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

### Filter to only see file-related syscalls

```bash
sudo ./sys_call_tracer.py -p 1234 -f open,read,write,close
```

### Trace only the first 50 syscalls

```bash
sudo ./sys_call_tracer.py -p 1234 -n 50
```

## Output Format

```
[2026-03-29 14:32:15.123] PID 1234 | open                 | entering | args: 140736214016000, 0, 0
[2026-03-29 14:32:15.124] PID 1234 | open                 | exiting  | ret: 3
[2026-03-29 14:32:15.125] PID 1234 | read                 | entering | args: 3, 140736214015488, 8192
[2026-03-29 14:32:15.126] PID 1234 | read                 | exiting  | ret: 1024
```

Each line shows:
- Timestamp with millisecond precision
- Process ID
- System call name (padded for alignment)
- Direction (entering/exiting)
- Arguments (for entering) or return value (for exiting)

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
