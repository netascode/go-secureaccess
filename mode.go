package secureaccess

import (
	"context"
	"sync"
)

// modeGate enforces mutual exclusion between READ (GET) traffic and WRITE
// (mutating) traffic
type modeGate struct {
	mu      sync.Mutex
	readers int
	writers int
	// idle is closed and replaced when a count drops to zero, waking all
	// waiters to re-check the counts.
	idle chan struct{}
}

// newModeGate returns an open gate.
func newModeGate() *modeGate {
	return &modeGate{idle: make(chan struct{})}
}

// enterRead blocks until no WRITE requests are active, then registers a READ
// request. It returns ctx.Err() if ctx is done first.
func (g *modeGate) enterRead(ctx context.Context) error {
	return g.enter(ctx, &g.readers, &g.writers)
}

// leaveRead unregisters a READ request registered by enterRead.
func (g *modeGate) leaveRead() {
	g.leave(&g.readers)
}

// enterWrite blocks until no READ requests are active, then registers a WRITE
// request. It returns ctx.Err() if ctx is done first.
func (g *modeGate) enterWrite(ctx context.Context) error {
	return g.enter(ctx, &g.writers, &g.readers)
}

// leaveWrite unregisters a WRITE request registered by enterWrite.
func (g *modeGate) leaveWrite() {
	g.leave(&g.writers)
}

func (g *modeGate) enter(ctx context.Context, own, other *int) error {
	for {
		g.mu.Lock()
		if *other == 0 {
			*own++
			g.mu.Unlock()
			return nil
		}
		idle := g.idle
		g.mu.Unlock()

		select {
		case <-idle:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *modeGate) leave(own *int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	*own--
	if *own == 0 {
		close(g.idle)
		g.idle = make(chan struct{})
	}
}
