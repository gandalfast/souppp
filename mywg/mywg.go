// Package mywg is an alternative GO waitgroup that similar to sync.WaitGroup,
// the key difference is mywg allow rountine to wait on a channel,
// so that the wait could be in a select statement;
package mywg

import (
	"sync/atomic"
)

type emptyType struct{}

var emptyVal = emptyType{}

// MyWG is the alternative waitgroup
type MyWG struct {
	val        *uint32
	doneChan   chan emptyType
	cancelChan chan emptyType
	// MyWG will send an empty struct into FinishChan once all done
	FinishChan chan emptyType
}

// NewMyWG creates a new MyWG instance
func NewMyWG() *MyWG {
	r := new(MyWG)
	r.val = new(uint32)
	r.doneChan = make(chan emptyType)
	r.cancelChan = make(chan emptyType)
	r.FinishChan = make(chan emptyType)
	go r.run()
	return r
}

func (wg *MyWG) run() {
	defer close(wg.doneChan)
	defer close(wg.cancelChan)
	for {
		select {
		case <-wg.doneChan:
			if newval := atomic.AddUint32(wg.val, ^uint32(0)); newval == 0 {
				wg.FinishChan <- emptyVal
				return
			}
		case <-wg.cancelChan:
			wg.FinishChan <- emptyVal
			return
		}
	}
}

// Add has semantics as sync.WaitGroup.Add(), only difference is this uses uint32
func (wg *MyWG) Add(delta uint32) {
	atomic.AddUint32(wg.val, delta)
}

// Wait has semantics as sync.WaitGroup.Add().
// it returns if wg internal value == 0
func (wg *MyWG) Wait() {
	defer close(wg.FinishChan)
	if atomic.LoadUint32(wg.val) == 0 {
		return
	}
	<-wg.FinishChan
}

// Done has semantics as sync.WaitGroup.Add()
func (wg *MyWG) Done() {
	wg.doneChan <- emptyVal
}

// Cancel stop the wg, cause Wait() to return, regardless if all is done or not;
// note: if there is no other routine is waiting, then there wg will have an internal routine still running
func (wg *MyWG) Cancel() {
	wg.cancelChan <- emptyVal
}
