package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed c/ebpf.o
var ebpfProg []byte

const (
	BPF_CONNECTIONS_NAME = "connections"
	BPF_CONFIG_NAME      = "config"
	BPF_ITER_NAME        = "dump_connections"
)

func main() {
	fmt.Printf("Hello.\n")
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		log.Fatalf("loading asset: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating eBPF collection: %w", err)
	}

	configMap, ok := coll.Maps[BPF_CONFIG_NAME]
	if !ok {
		log.Fatalf("bpf map %q not found", BPF_CONFIG_NAME)
	}
	configMap.Put(uint64(0), uint64(25))

	connMap, ok := coll.Maps[BPF_CONNECTIONS_NAME]
	if !ok {
		log.Fatalf("bpf map %q not found", BPF_CONNECTIONS_NAME)
	}

	connMap.Put(uint64(10), uint64(2))
	connMap.Put(uint64(20), uint64(3))
	connMap.Put(uint64(30), uint64(3))
	connMap.Put(uint64(40), uint64(3))

	dumpConn, ok := coll.Programs[BPF_ITER_NAME]
	if !ok {
		log.Fatalf("bpf iterator %q not found", BPF_ITER_NAME)
	}
	dumpConnIter, err := link.AttachIter(link.IterOptions{
		Program: dumpConn,
		Map:     connMap,
	})
	if err != nil {
		log.Fatalf("%s", err)
	}

	for i := 0; i < 2; i++ {
		file, err := dumpConnIter.Open()
		if err != nil {
			log.Fatalf("Can't open iter instance: %s", err)
		}
		defer file.Close()

		contents, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatalf("Can't read iter instance: %s", err)
		}
		fmt.Printf("## i=%d\n%s\n", i, string(contents))
	}
}
