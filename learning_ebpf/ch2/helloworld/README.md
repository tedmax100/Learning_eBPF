# Hello World
---

## Launch steps
```
go generate
go build && sudo ./ebpf-test    
```

## Watch log
`sudo cat /sys/kernel/debug/tracing/trace_pipe`