package runtime

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"cloudattrib/internal/config"
)

func TestServiceResponseWriteTimeoutReleasesStalledClient(t *testing.T) {
	configuration := config.Default()
	configuration.Limits.Target.TargetDeadline = 30 * time.Millisecond
	configuration.Limits.SynchronousAdmissionTimeout = 30 * time.Millisecond
	configuration.Limits.ResponseWriteGrace = 30 * time.Millisecond
	started := make(chan struct{})
	finished := make(chan error, 1)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		block := make([]byte, 64<<10)
		for {
			if _, err := writer.Write(block); err != nil {
				finished <- err
				return
			}
		}
	})
	server := newServiceHTTPServer(handler, configuration, context.Background())
	if server.WriteTimeout != 90*time.Millisecond {
		t.Fatalf("write timeout = %v", server.WriteTimeout)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	// The client deliberately leaves the response unread. The server write
	// deadline must unblock the handler's eventually full socket buffer.
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled client retained the handler past its write deadline")
	}
}
