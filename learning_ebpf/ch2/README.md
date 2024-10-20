# Exercises
Here are some optional activities you might like to try (or think about) if you want to explore “Hello World” a bit further:

1. Adapt the []`hello-buffer.py`](https://github.com/lizrice/learning-ebpf/blob/main/chapter2/hello-buffer.py) eBPF program to output different trace messages for odd and even process IDs.

2. Modify [hello-map.py](https://github.com/lizrice/learning-ebpf/blob/main/chapter2/hello-map.py) so that the eBPF code gets triggered by more than one syscall. For example, `openat()` is commonly called to open files, and `write()` is called to write data to a file. You can start by attaching the hello eBPF program to multiple syscall kprobes. Then try having modified versions of the hello eBPF program for different syscalls, demonstrating that you can access the same map from multiple different programs.

3. The [hello-tail.py](https://github.com/lizrice/learning-ebpf/blob/main/chapter2/hello-tail.py) eBPF program is an example of a program that attaches to the `sys_enter` raw tracepoint that is hit whenever any syscall is called. Change hello-map.py to show the total number of syscalls made by each user ID, by attaching it to that same `sys_enter` raw tracepoint.

Here’s some example output I got after making that change:
```
$ ./hello-map.py 
ID 104: 6     ID 0: 225
ID 104: 6     ID 101: 34    ID 100: 45    ID 0: 332     ID 501: 19
ID 104: 6     ID 101: 34    ID 100: 45    ID 0: 368     ID 501: 38
ID 104: 6     ID 101: 34    ID 100: 45    ID 0: 533     ID 501: 57
```

4. The [`RAW_TRACEPOINT_PROBE` macro provided by BCC](https://oreil.ly/kh-j4) simplifies attaching to raw tracepoints, telling the user space BCC code to automatically attach it to a specified tracepoint. Try it in hello-tail.py, like this:

- Replace the definition of the `hello()` function with `RAW_TRACEPOINT_PROBE(sys_enter)`.

- Remove the explicit attachment call `b.attach_raw_tracepoint()` from the Python code.

You should see that BCC automatically creates the attachment and the program works exactly the same. This is an example of the many convenient macros that BCC provides.

5. You could further adapt `hello_map.py` so that the key in the hash table identifies a particular syscall (rather than a particular user). The output will show how many times that syscall has been called across the whole system.

