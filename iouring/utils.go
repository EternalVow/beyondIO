package iouring

import "unsafe"

func clz(x uint32) uint32 {
	if x == 0 {
		return 32
	}
	n := 0
	for ; x > 0; n++ {
		x >>= 1
	}
	return uint32(32 - n)
}
func fls(x uint) uint {
	if x == 0 {
		return 0
	}
	return 8*uint(unsafe.Sizeof(x)) - uint(clz(uint32(x)))
}

func roundupPow2(depth uint) uint {
	return 1 << fls(depth-1)
}
