all:
	clang -target bpf -O2 -g -c -x c c/ebpf.c -o c/ebpf.o
	go build -o main main.go

clean:
	rm -f c/ebpf.o main

test/cilium:
	sudo ./main

test/cilium_with_strace:
	sudo strace -f -e bpf,close ./main

test/bpftool:
	sudo rm -f /sys/fs/bpf/map_for_iter /sys/fs/bpf/myiter
	sudo bpftool map create /sys/fs/bpf/map_for_iter type hash key 8 value 8 entries 1024 name map_for_iter
	sudo bpftool iter pin c/ebpf.o /sys/fs/bpf/myiter map pinned /sys/fs/bpf/map_for_iter
	sudo cat /sys/fs/bpf/myiter
