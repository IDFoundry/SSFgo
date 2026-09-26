package memstore_test

import (
	"testing"

	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/storage/storagetest"
)

func TestContract(t *testing.T) {
	storagetest.StreamStore(t, func(*testing.T) storage.StreamStore { return memstore.New() })
}
