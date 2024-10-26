package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const mapKey uint32 = 0

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := hellomapObjects{}
	if err := loadHellomapObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.Hello, nil)
	if err != nil {
		log.Fatalf("opening tracepoint:%s", err)
	}
	defer kp.Close()

	// 定期讀取 counter_table，輸出 BPF 程式收集的計數資料
	go func() {
		for {
			time.Sleep(2 * time.Second)

			var mapKey uint32
			var counter uint64

			iter := objs.CounterTable.Iterate()
			for iter.Next(&mapKey, &counter) {
				log.Printf("UID %d called execve %d times\n", mapKey, counter)
			}
			if err := iter.Err(); err != nil {
				log.Printf("failed to iterate over map: %v", err)
			}
		}
	}()

	<-stopper
	log.Println("Received signal, shutting down...")
}
