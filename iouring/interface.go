package iouring

import (
	"errors"
	"unsafe"
)

type IIouring interface {
	QueueInitParams(entries uint, ioUring *Ring, p *Params) error
	QueueInit(entries uint, ioUring *Ring, flags uint32) error
	QueueInitMem(entries uint, ioUring *Ring, p *Params, buf unsafe.Pointer, bufSize uint) error
	QueueInitTryNosqarr(entries uint, ioUring *Ring, p *Params, buf unsafe.Pointer, bufSize uint) error
}

func InitIouring() (*Iouring, error) {
	return &Iouring{}, nil
}

type Iouring struct {
}

func (i Iouring) QueueInitParams(entries uint, ioUring *Ring, p *Params) error {
	ret := ioUringQueueInitParams(entries, ioUring, p, nil, 0)
	if ret != 0 {
		return errors.New("Failed to initialize Iouring queue")
	}
	return nil
}

func (i Iouring) QueueInitTryNosqarr(entries uint, ioUring *Ring, p *Params, buf unsafe.Pointer, bufSize uint) error {
	var flags = p.Flags

	p.Flags |= SetupNoSQArray
	ret := ioUringQueueInitParams(entries, ioUring, p, buf, bufSize)

	/* don't fallback if explicitly asked for NOSQARRAY */
	if ret != _EINVAL || (flags&SetupNoSQArray) == 0 {
		//return ret, nil
		return errors.New("ioUringQueueInitParams Failed to initialize Iouring queue")
	}

	p.Flags = flags
	ret = ioUringQueueInitParams(entries, ioUring, p, buf, bufSize)
	if ret != 0 {
		return errors.New("Failed to initialize Iouring queue")
	}
	return nil
}

func (i Iouring) QueueInitMem(entries uint, ioUring *Ring, p *Params, buf unsafe.Pointer, bufSize uint) error {
	p.Flags |= SetupNoMmap
	return i.QueueInitTryNosqarr(entries, ioUring, p, buf, bufSize)
}

func (i Iouring) QueueInit(entries uint, ioUring *Ring, flags uint32) error {
	p := &Params{
		Flags: flags,
	}
	return i.QueueInitParams(entries, ioUring, p)
}
