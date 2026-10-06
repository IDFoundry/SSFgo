package memstore_test

import (
	"testing"

	"github.com/idfoundry/ssfgo/storage"
	"github.com/idfoundry/ssfgo/storage/memstore"
	"github.com/idfoundry/ssfgo/storage/storagetest"
)

func TestContract(t *testing.T) {
	storagetest.StreamStore(t, func(*testing.T) storage.StreamStore { return memstore.NewStreamStore() })
}

func TestReplayContract(t *testing.T) {
	storagetest.ReplayStore(t, func(*testing.T) storage.ReplayStore { return memstore.NewReplayStore() })
}

func TestRevocationContract(t *testing.T) {
	storagetest.RevocationStore(t, func(*testing.T) storage.RevocationStore { return memstore.NewRevocationStore() })
}
