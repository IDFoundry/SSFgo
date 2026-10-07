module github.com/idfoundry/ssfgo/examples/session-revocation

go 1.26.6

require github.com/idfoundry/ssfgo v0.0.0-00010101000000-000000000000

// The example always builds against this checkout of the library, not a
// published release, so a library change and the example using it land
// together.
replace github.com/idfoundry/ssfgo => ../..
