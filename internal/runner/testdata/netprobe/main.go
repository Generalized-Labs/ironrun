// netprobe is a test fixture: it attempts a single outbound TCP connection and
// exits 0 if it succeeds, 1 if it fails. Under ironrun's no_network isolation
// the dial is denied (macOS sandbox) or unreachable (Linux netns), so a non-zero
// exit means isolation blocked the network. It is internet-independent: the
// isolation failure surfaces before any real connectivity matters.
package main

import (
	"net"
	"os"
	"time"
)

func main() {
	c, err := net.DialTimeout("tcp", "1.1.1.1:53", 3*time.Second)
	if err != nil {
		os.Exit(1) // blocked or unreachable
	}
	_ = c.Close()
	os.Exit(0) // connected — network was reachable
}
