package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed c/ebpf.o
var ebpfProg []byte

const (
	BPF_ITER_NAME = "dump_connections"
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

	dumpConn, ok := coll.Programs[BPF_ITER_NAME]
	if !ok {
		log.Fatalf("bpf iterator %q not found", BPF_ITER_NAME)
	}
	dumpConnIter, err := link.AttachIter(link.IterOptions{
		Program: dumpConn,
	})
	if err != nil {
		log.Fatalf("%s", err)
	}
	fmt.Printf("dumpConnIter: %v\n", dumpConnIter)
}
