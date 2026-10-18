package audit

import (
	"bytes"
	"net/http"
	"sync"
	"time"
)

// HTTPSink ships events as newline-delimited JSON batches via POST. Writes
// never block the proxy: events queue in memory and are dropped (counted in
// Dropped) if the collector is down and the queue fills.
type HTTPSink struct {
	url    string
	header map[string]string
	client *http.Client
	ch     chan []byte
	done   chan struct{}
	wg     sync.WaitGroup

	mu      sync.Mutex
	dropped int64

	closeOnce sync.Once
}

// NewHTTPSink starts the background shipper.
func NewHTTPSink(url string, header map[string]string) *HTTPSink {
	h := &HTTPSink{url: url, header: header, client: &http.Client{Timeout: 10 * time.Second},
		ch: make(chan []byte, 4096), done: make(chan struct{})}
	h.wg.Add(1)
	go h.run()
	return h
}

// Dropped returns how many events were discarded.
func (h *HTTPSink) Dropped() int64 { h.mu.Lock(); defer h.mu.Unlock(); return h.dropped }

func (h *HTTPSink) Write(p []byte) (int, error) {
	select {
	case h.ch <- append([]byte(nil), p...):
	default:
		h.mu.Lock()
		h.dropped++
		h.mu.Unlock()
	}
	return len(p), nil
}

func (h *HTTPSink) run() {
	defer h.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var buf bytes.Buffer
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		h.post(buf.Bytes())
		buf.Reset()
	}
	for {
		select {
		case b := <-h.ch:
			buf.Write(b)
			if buf.Len() > 256<<10 {
				flush()
			}
		case <-t.C:
			flush()
		case <-h.done:
			for {
				select {
				case b := <-h.ch:
					buf.Write(b)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (h *HTTPSink) post(body []byte) {
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		for k, v := range h.header {
			req.Header.Set(k, v)
		}
		resp, err := h.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return
			}
			if resp.StatusCode < 500 && resp.StatusCode != 429 {
				return
			}
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	h.mu.Lock()
	h.dropped++
	h.mu.Unlock()
}

// Close flushes queued events and stops the shipper.
func (h *HTTPSink) Close() error {
	h.closeOnce.Do(func() { close(h.done) }) // a second Close must not panic
	h.wg.Wait()
	return nil
}
