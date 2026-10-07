package main

// SA-GO-01: Unsafe pointer arithmetic bypasses memory safety
import "unsafe"

func readMemory(data []byte) byte {
	ptr := unsafe.Pointer(&data[0])
	return *(*byte)(ptr)
}
