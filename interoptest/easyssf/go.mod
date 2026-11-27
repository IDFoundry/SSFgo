module github.com/idfoundry/ssfgo/interoptest/easyssf

go 1.26.10

require (
	github.com/easyssf/easyssf-go v0.7.0
	github.com/idfoundry/ssfgo v0.0.0
)

require github.com/go-jose/go-jose/v4 v4.1.6 // indirect

replace github.com/idfoundry/ssfgo => ../..
