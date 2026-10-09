// netprobe is a test fixture: it attempts a single outbound TCP connection and
// prints a DISTINCT marker so a test can tell "network blocked" apart from "the
// binary crashed before dialing". Under ironrun's no_network isolation the dial
// is denied (macOS sandbox) or unreachable (Linux netns), so it prints
// DIAL_BLOCKED and exits 1; with the network open it prints DIAL_OK and exits 0.
// It is internet-independent: the isolation failure surfaces before any real
// connectivity matters.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err != nil {
		fmt.Println("DIAL_BLOCKED:", err)
		os.Exit(1) // blocked or unreachable
	}
	_ = c.Close()
	fmt.Println("DIAL_OK")
	os.Exit(0) // connected — network was reachable
}
