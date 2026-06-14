// ironrun-action is the GitHub Actions entrypoint binary.
// It is built separately and embedded in the Action Docker image.
package main

import (
	"os"

	"github.com/generalized-labs/ironrun/action"
)

func main() {
	os.Exit(action.Run())
}
