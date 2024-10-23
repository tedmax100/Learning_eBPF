package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := hellowroldObjects{}
	if err := loadHellowroldObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleTp, nil)
	if err != nil {
		log.Fatalf("opening tracepoint:%s", err)
	}
	defer kp.Close()

	<-stopper

}
