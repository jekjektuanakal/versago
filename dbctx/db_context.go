package dbctx

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jekjektuanakal/versago/errkind"
)

type DBContext interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type DBTransaction interface {
	DBContext
	Commit() error
	Rollback() error
}

func BeginTransaction(db DBContext) (*sql.Tx, error) {
	switch dbContext := db.(type) {
	case nil:
		return nil, fmt.Errorf("db is nil: %w", errkind.ErrInvalidArgument)
	case *sql.DB:
		return dbContext.Begin()
	case *sql.Tx:
		return dbContext, nil
	default:
		return nil, fmt.Errorf("unknown db type: %w", errkind.ErrNotImplemented)
	}
}
