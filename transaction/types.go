package transaction

import (
	"github.com/blockcypher/libgrin/core"
	"github.com/google/uuid"
)

type Transaction struct {
	core.Transaction
	ID uuid.UUID
}
