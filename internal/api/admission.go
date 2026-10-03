package api

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

type synchronousGate struct {
	// The configured channel capacity is the maximum number of API requests
	// allowed to wait for the shared target controller at one time.
	waiters chan struct{}
	timeout time.Duration
	waiting atomic.Int64
}

type admissionWait struct {
	ctx      context.Context
	parent   context.Context
	cancel   context.CancelFunc
	release  func()
	admitted *atomic.Bool
}

func newSynchronousGate(maxWaiters int, timeout time.Duration) (*synchronousGate, error) {
	if maxWaiters <= 0 || timeout <= 0 {
		return nil, model.NewError(model.CodeInvalidOptions, "synchronous admission limits must be positive", nil)
	}
	return &synchronousGate{waiters: make(chan struct{}, maxWaiters), timeout: timeout}, nil
}

func (g *synchronousGate) begin(parent context.Context) (*admissionWait, error) {
	select {
	case <-parent.Done():
		return nil, model.NewError(model.CodeCancelled, "request cancelled before admission", parent.Err())
	case g.waiters <- struct{}{}:
	default:
		return nil, model.NewError(model.CodeQueueCapacityExceeded, "synchronous admission waiters are full", nil)
	}
	g.waiting.Add(1)
	var once sync.Once
	release := func() {
		once.Do(func() {
			<-g.waiters
			g.waiting.Add(-1)
		})
	}
	if err := parent.Err(); err != nil {
		release()
		return nil, model.NewError(model.CodeCancelled, "request cancelled before admission", err)
	}
	waitContext, cancel := context.WithTimeout(parent, g.timeout)
	admitted := new(atomic.Bool)
	onAdmitted := func() {
		admitted.Store(true)
		release()
	}
	return &admissionWait{
		ctx: policy.WithSynchronousAdmission(waitContext, parent, onAdmitted), parent: parent,
		cancel: cancel, release: release, admitted: admitted,
	}, nil
}

func (w *admissionWait) finish() {
	w.cancel()
	w.release()
}

func (w *admissionWait) error(err error) error {
	if !w.admitted.Load() && w.ctx.Err() == context.DeadlineExceeded && w.parent.Err() == nil {
		return model.NewError(model.CodeQueueCapacityExceeded, "synchronous admission deadline exceeded", err)
	}
	return err
}
