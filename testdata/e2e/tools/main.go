// The HTTP server an artifact image carries. It is compiled to a static binary
// and downloaded as an artifact, so the image needs neither a package nor an
// interpreter to run it.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
)

func main() {
	listen := flag.String("listen", "", "port to listen on")
	flag.Parse()

	port := *listen
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "hello from vapor")
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	fmt.Fprintln(os.Stderr, "listening on", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
