// Copyright (c) 2019 The Gnet Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd
// +build darwin dragonfly freebsd linux netbsd openbsd

package beyondIO

import (
	"context"
	"github.com/EternalVow/beyondIO/iouring"
	"github.com/baickl/logger"
	"github.com/panjf2000/gnet/v2/pkg/errors"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

type engineRing struct {
	iouring.Iouring

	engine *engine
}

type engine struct {
	listeners  map[int]*listener // listeners for accepting incoming connections
	opts       *Options          // options with engine
	ingress    *eventloop        // main event-loop that monitors all listeners
	inShutdown int32             // whether the engine is in shutdown
	ticker     struct {
		ctx    context.Context    // context for ticker
		cancel context.CancelFunc // function to stop the ticker
	}
	workerPool struct {
		*errgroup.Group

		shutdownCtx context.Context
		shutdown    context.CancelFunc
		once        sync.Once
	}
	eventHandler EventHandler // user eventHandler
	eventLoops   []*eventloop

	ctx  context.Context // context for ticker
	ring engineRing
}

func (eng *engine) isInShutdown() bool {
	return atomic.LoadInt32(&eng.inShutdown) == 1
}

// shutdown signals the engine to shut down.
func (eng *engine) shutdown(err error) {
	if err != nil && err != errors.ErrEngineShutdown {
		logger.Errorf("engine is being shutdown with error: %v", err)
	}

	eng.workerPool.once.Do(func() {
		eng.workerPool.shutdown()
	})
}

func (eng *engine) closeEventLoops() {
	for _, el := range eng.eventLoops {
		for _, ln := range el.listeners {
			ln.close()
		}
		//_ = el.selector.Close()
	}
	if eng.ingress != nil {
		for _, ln := range eng.listeners {
			ln.close()
		}
		//err := eng.ingress.selector.Close()
		//if err != nil {
		//	logger.Errorf("failed to close selector when stopping engine: %v", err)
		//}
	}
}

func (eng *engine) runEventLoops(numEventLoop int) error {
	var el0 *eventloop
	lns := eng.listeners
	// Create loops locally and bind the listeners.
	for i := 0; i < numEventLoop; i++ {
		if i > 0 {
			lns = make(map[int]*listener, len(eng.listeners))
			for _, l := range eng.listeners {
				ln, err := initListener(l.network, l.address, eng.opts)
				if err != nil {
					return err
				}
				lns[ln.fd] = ln
			}
		}
		p := NewIoUringSelector(eng)
		el := new(eventloop)
		el.listeners = lns
		el.engine = eng
		el.selector = p
		el.buffer = make([]byte, eng.opts.ReadBufferCap)
		el.connections = NewConnections()
		el.eventHandler = eng.eventHandler
		for _, ln := range lns {
			if err := el.selector.AddRead(eng.ctx, ln.fd, false); err != nil {
				return err
			}
		}
		eng.eventLoops = append(eng.eventLoops, el)

		// Start the ticker.
		if eng.opts.Ticker && el.idx == 0 {
			el0 = el
		}
	}

	// Start event-loops in background.
	for _, el := range eng.eventLoops {
		eng.workerPool.Go(el.run)
	}

	if el0 != nil {
		eng.workerPool.Go(func() error {
			el0.ticker(eng.ticker.ctx)
			return nil
		})
	}

	return nil
}

func (eng *engine) activateReactors(numEventLoop int) error {
	for i := 0; i < numEventLoop; i++ {
		p := NewIoUringSelector(eng)
		el := new(eventloop)
		el.listeners = eng.listeners
		el.engine = eng
		el.selector = p
		el.buffer = make([]byte, eng.opts.ReadBufferCap)
		el.connections = NewConnections()
		el.eventHandler = eng.eventHandler
		eng.eventLoops = append(eng.eventLoops, el)
	}

	// Start sub reactors in background.
	for _, el := range eng.eventLoops {
		eng.workerPool.Go(el.orbit)
	}

	p := NewIoUringSelector(eng)
	el := new(eventloop)
	el.listeners = eng.listeners
	el.idx = -1
	el.engine = eng
	el.selector = *p
	el.eventHandler = eng.eventHandler
	for _, ln := range eng.listeners {
		if err := el.selector.AddRead(eng.ctx, ln.fd, false); err != nil {
			return err
		}
	}
	eng.ingress = el

	// Start main reactor in background.
	eng.workerPool.Go(el.rotate)

	// Start the ticker.
	if eng.opts.Ticker {
		eng.workerPool.Go(func() error {
			eng.ingress.ticker(eng.ticker.ctx)
			return nil
		})
	}

	return nil
}

func (eng *engine) start(numEventLoop int) error {
	if eng.opts.ReusePort {
		return eng.runEventLoops(numEventLoop)
	}

	return eng.activateReactors(numEventLoop)
}

func (eng *engine) stop() {
	// Wait on a signal for shutdown
	<-eng.workerPool.shutdownCtx.Done()

	err := eng.eventHandler.OnShutdown(nil)
	if err != nil {
		logger.Errorf("engine OnShutdown error: %v", err)
	}

	//if eng.ingress != nil {
	//	err := eng.ingress.selector.Trigger(queue.HighPriority, func(_ interface{}) error { return errors.ErrEngineShutdown }, nil)
	//	if err != nil {
	//		logger.Errorf("failed to enqueue shutdown signal of high-priority for main event-loop: %v", err)
	//	}
	//}

	// Stop the ticker.
	if eng.ticker.cancel != nil {
		eng.ticker.cancel()
	}

	if err := eng.workerPool.Wait(); err != nil {
		logger.Errorf("engine shutdown error: %v", err)
	}

	// Close all listeners and pollers of event-loops.
	eng.closeEventLoops()
	eng.ring.QueueExit(eng.ring.Ring)

	// Put the engine into the shutdown state.
	atomic.StoreInt32(&eng.inShutdown, 1)
}

func run(eventHandler EventHandler, listeners []*listener, options *Options, addrs []string) error {
	// Figure out the proper number of event-loop to run.
	numEventLoop := 1
	if options.Multicore {
		numEventLoop = EventLoopForCpu
	}
	if options.NumEventLoop > 0 {
		numEventLoop = options.NumEventLoop
	}
	if numEventLoop > EventLoopIndexMax {
		numEventLoop = EventLoopIndexMax
	}

	lns := make(map[int]*listener, len(listeners))
	for _, ln := range listeners {
		lns[ln.fd] = ln
	}
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	eng := engine{
		listeners: lns,
		opts:      options,
		workerPool: struct {
			*errgroup.Group
			shutdownCtx context.Context
			shutdown    context.CancelFunc
			once        sync.Once
		}{&errgroup.Group{}, shutdownCtx, shutdown, sync.Once{}},
		eventHandler: eventHandler,
	}
	ring, err := iouring.InitIouring()
	if err != nil {
		return err
	}
	eng.ring = engineRing{
		Iouring: *ring,
		engine:  &eng,
	}

	eng.ring.QueueInit(8, ring.Ring, 0)

	if eng.opts.Ticker {
		eng.ticker.ctx, eng.ticker.cancel = context.WithCancel(context.Background())
	}

	if err := eng.eventHandler.OnStart(nil); err != nil {
		return err
	}

	if err := eng.start(numEventLoop); err != nil {
		eng.closeEventLoops()
		return err
	}
	defer eng.stop()

	//for _, addr := range addrs {
	//	allEngines.Store(addr, &eng)
	//}

	return nil
}
