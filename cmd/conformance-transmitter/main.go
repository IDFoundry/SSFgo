// Command conformance-transmitter runs an SSFgo Transmitter configured for
// the OpenID Foundation SSF conformance suite's CAEP Interoperability
// Profile Transmitter plan, with in-memory storage. The harness itself is
// internal/conformance/txharness; storage/sqlstore/cmd/conformance-transmitter
// runs the same harness on storage/sqlstore.
//
// All state is in memory and every key is generated at startup.
//
//	go run ./cmd/conformance-transmitter -issuer https://host.docker.internal:9443/ssfgo
package main

import (
	"flag"
	"log"

	"github.com/idfoundry/ssfgo/internal/conformance/txharness"
	"github.com/idfoundry/ssfgo/storage/memstore"
)

func main() {
	opts := txharness.RegisterFlags(flag.CommandLine)
	flag.Parse()
	log.Fatal(txharness.Run(opts, memstore.NewStreamStore()))
}
