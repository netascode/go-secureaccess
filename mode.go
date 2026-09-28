package secureaccess

// runModeGate is the single arbiter for a Client's READ/WRITE gate. It reads
// signed deltas (+1 on request start, -1 on request end) from readers and
// writers. While one side's count is nonzero, only that side's channel is
// drained, so a send from the other side blocks until the count returns to
// zero — enforcing mutual exclusion between GET traffic and mutating
// traffic without a mutex.
func runModeGate(readers, writers chan int) {
	var readerNum, writerNum int
	for {
		select {
		case delta := <-readers:
			readerNum += delta
			for readerNum != 0 {
				readerNum += <-readers
			}

		case delta := <-writers:
			writerNum += delta
			for writerNum != 0 {
				writerNum += <-writers
			}
		}
	}
}
