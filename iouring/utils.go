package iouring

// 最接近的最大2的指数次幂
// 找出当前数的二级制中最大位为1位的位置，然后用1左移位数即可。
// The closest exponent to the maximum power of 2
// Find the position of the current number in the binary system where the maximum bit is 1, and then shift the number of bits left by 1.
func roundupPow2(x uint) uint {
	if x == 0 {
		return 1
	}
	x--
	for x&(x-1) != 0 {
		x &= x - 1
	}
	return x << 1
}
