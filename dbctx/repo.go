package dbctx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"github.com/gertd/go-pluralize"
	"github.com/iancoleman/strcase"
	"golang.org/x/exp/slices"

	"github.com/jekjektuanakal/versago/errkind"
)

type Pagination struct {
	Offset int
	Limit  int
}

type Order struct {
	Field string
	Desc  bool
}

type Filters map[string]any

type Fields map[string]any

type UpdateOptions struct {
	Filters Filters
}

type FindOptions struct {
	Filters    Filters
	Pagination *Pagination
	Order      *Order
}

type Repo[T any] interface {
	Create(ctx context.Context, db DBContext, item *T) error
	UpdateOne(ctx context.Context, db DBContext, item T) error
	UpdateMany(ctx context.Context, db DBContext, fields Fields, filters Filters) error
	DeleteOne(ctx context.Context, db DBContext, item T) error
	DeleteMany(ctx context.Context, db DBContext, filters Filters) error
	FindOne(ctx context.Context, db DBContext, filters Filters) (*T, error)
	FindMany(ctx context.Context, db DBContext, opts FindOptions) ([]T, error)
}

type ColumnKind int

const (
	ValueColumn ColumnKind = iota
	KeyColumn
	GeneratedKeyColumn
	CreatedAtColumn
	UpdatedAtColumn
)

type Column struct {
	Name string
	Kind ColumnKind
}

type SQLRepoConfig[T any] struct {
	Table          string
	Columns        []Column
	MapScan        func(item *T) []any
	NoSoftDelete   bool
	NoCreateUpdate bool
}

type PgSQLRepo[T any] struct {
	table                string
	columns              []Column
	mapScan              func(item *T) []any
	columnNames          []string
	idColumnIndex        int
	createTsColumnIndex  int
	updateTsColumnIndex  int
	findStatement        string
	createStatement      string
	updateOneStatement   string
	deleteOneStatement   string
	deleteOneScanIndices []int
	deleteManyStatement  string
}

func NewPgSQLRepo[T any](cfg SQLRepoConfig[T]) (*PgSQLRepo[T], error) {
	var t T
	ty := reflect.TypeOf(t)

	if ty.Kind() != reflect.Struct {
		return nil, fmt.Errorf("entity must be a struct : %w", errkind.ErrInvalidArgument)
	}

	if cfg.Table == "" {
		cfg.Table = makeDefaultTableName[T]()
	}

	if len(cfg.Columns) == 0 {
		if _, found := ty.FieldByName("ID"); !found {
			return nil, fmt.Errorf("entity must have an ID field : %w", errkind.ErrInvalidArgument)
		}

		cfg.Columns = makeDefaultColumns[T]()
	}

	if cfg.MapScan == nil {
		cfg.MapScan = makeDefaultMapScan[T]()
	}

	idColumnIndex := -1
	createdTsColumnIndex := -1
	updatedTsColumnIndex := -1
	keyColumnNames := make([]string, 0)
	columnNames := make([]string, 0)

	for i, column := range cfg.Columns {
		switch column.Kind {
		case GeneratedKeyColumn:
			if idColumnIndex != -1 {
				return nil, fmt.Errorf("entity must have only one generated key column: %w", errkind.ErrInvalidArgument)
			}

			idColumnIndex = i

			keyColumnNames = append(keyColumnNames, column.Name)
		case CreatedAtColumn:
			createdTsColumnIndex = i

			keyColumnNames = append(keyColumnNames, column.Name)
		case UpdatedAtColumn:
			updatedTsColumnIndex = i

			keyColumnNames = append(keyColumnNames, column.Name)
		case KeyColumn:
			keyColumnNames = append(keyColumnNames, column.Name)
		}

		columnNames = append(columnNames, column.Name)
	}

	if len(keyColumnNames) == 0 {
		return nil, fmt.Errorf("entity must have at least one key column : %w", errkind.ErrInvalidArgument)
	}

	lenMapScan := len(cfg.MapScan(&t))

	if lenMapScan == 0 || lenMapScan > ty.NumField() {
		return nil, fmt.Errorf("map scan function must return at least one field : %w", errkind.ErrInvalidArgument)
	}

	if len(cfg.Columns) != lenMapScan {
		return nil, fmt.Errorf("map scan length must be equal number of columns: %w", errkind.ErrInvalidArgument)
	}

	findStatement := makeFindStatement(cfg.Table, cfg.Columns, !cfg.NoSoftDelete)
	createStatement := makeCreateStatement(cfg.Table, cfg.Columns, !cfg.NoCreateUpdate)
	updateOneStatement := makeUpdateOneStatement(cfg.Table, cfg.Columns, !cfg.NoCreateUpdate, !cfg.NoSoftDelete)
	deleteOneStatement := makeDeleteOneStatement(cfg.Table, cfg.Columns, !cfg.NoSoftDelete)

	var deleteManyStatement string

	if !cfg.NoSoftDelete {
		deleteManyStatement = fmt.Sprintf("UPDATE %s SET deleted_at = NOW() WHERE deleted_at IS NULL ", cfg.Table)
	} else {
		deleteManyStatement = fmt.Sprintf("DELETE FROM %s WHERE 1=1 ", cfg.Table)
	}

	deleteOneScanIndices := makeDeleteOneScanIndices(cfg.Columns)

	return &PgSQLRepo[T]{
			table:                cfg.Table,
			columns:              cfg.Columns,
			columnNames:          columnNames,
			idColumnIndex:        idColumnIndex,
			createTsColumnIndex:  createdTsColumnIndex,
			updateTsColumnIndex:  updatedTsColumnIndex,
			findStatement:        findStatement,
			createStatement:      createStatement,
			updateOneStatement:   updateOneStatement,
			deleteOneStatement:   deleteOneStatement,
			deleteOneScanIndices: deleteOneScanIndices,
			deleteManyStatement:  deleteManyStatement,
			mapScan:              cfg.MapScan,
		},
		nil
}

func (r PgSQLRepo[T]) Create(ctx context.Context, db DBContext, item *T) error {
	scanArgs := r.mapScan(item)
	createArgs := make([]any, 0, len(scanArgs))

	for i, column := range r.columns {
		switch column.Kind {
		case KeyColumn, ValueColumn:
			createArgs = append(createArgs, scanArgs[i])
		case GeneratedKeyColumn, CreatedAtColumn, UpdatedAtColumn:
		}
	}

	return db.QueryRowContext(ctx, r.createStatement, createArgs...).Scan(scanArgs...)
}

func (r PgSQLRepo[T]) UpdateOne(ctx context.Context, db DBContext, item T) error {
	scanArgs := r.mapScan(&item)
	updateArgs := make([]any, 0, len(scanArgs))

	for i, column := range r.columns {
		switch column.Kind {
		case GeneratedKeyColumn, KeyColumn, ValueColumn:
			updateArgs = append(updateArgs, scanArgs[i])
		case CreatedAtColumn, UpdatedAtColumn:
		}
	}

	result, err := db.ExecContext(ctx, r.updateOneStatement, updateArgs...)
	if err != nil {
		return fmt.Errorf("error updating one: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("item not found: %w", errkind.ErrNotFound)
	}

	return nil
}

func (r PgSQLRepo[T]) UpdateMany(ctx context.Context, db DBContext, fields Fields, filters Filters) error {
	if len(fields) == 0 {
		return fmt.Errorf("fields must not be empty: %w", errkind.ErrInvalidArgument)
	}

	argValues := make([]any, 0, len(fields)+len(filters))
	i := 1

	setClause := ""

	for column, value := range fields {
		if !slices.Contains(r.columnNames, column) {
			return fmt.Errorf("column %s not found: %w", column, errkind.ErrInvalidArgument)
		}

		if column == "created_at" || column == "updated_at" {
			continue
		}

		argValues = append(argValues, value)
		setClause += fmt.Sprintf("%s=$%d, ", column, i)
		i++
	}

	setClause += "updated_at = NOW()"

	filterClause := "deleted_at IS NULL "

	for column, value := range filters {
		if !slices.Contains(r.columnNames, column) {
			return fmt.Errorf("column %s not found: %w", column, errkind.ErrInvalidArgument)
		}

		argValues = append(argValues, value)
		filterClause += fmt.Sprintf("AND %s=$%d ", column, i)
		i++
	}

	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s", r.table, setClause, filterClause)

	_, err := db.ExecContext(ctx, query, argValues...)
	if err != nil {
		return fmt.Errorf("error updating many: %w", err)
	}

	return nil
}

func (r PgSQLRepo[T]) DeleteOne(ctx context.Context, db DBContext, item T) error {
	scanArgs := r.mapScan(&item)
	keyScanArgs := make([]any, 0, len(r.deleteOneScanIndices))

	for _, i := range r.deleteOneScanIndices {
		keyScanArgs = append(keyScanArgs, scanArgs[i])
	}

	result, err := db.ExecContext(ctx, r.deleteOneStatement, keyScanArgs...)
	if err != nil {
		return fmt.Errorf("error deleting one: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error getting rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("item not found: %w", errkind.ErrNotFound)
	}

	return nil
}

func (r PgSQLRepo[T]) DeleteMany(ctx context.Context, db DBContext, filters Filters) error {
	filterClause, filterValues, err := makeFilter(filters, r.columnNames)
	if err != nil {
		return fmt.Errorf("error making filter clause: %w: %w", errkind.ErrInvalidArgument, err)
	}

	query := r.deleteManyStatement + filterClause

	_, err = db.ExecContext(ctx, query, filterValues...)

	return err
}

func (r PgSQLRepo[T]) FindOne(ctx context.Context, db DBContext, filters Filters) (*T, error) {
	query := r.findStatement

	filterClause, filterValues, err := makeFilter(filters, r.columnNames)
	if err != nil {
		return nil, fmt.Errorf("error making filter clause: %w: %w", errkind.ErrInvalidArgument, err)
	}

	query += filterClause

	row := db.QueryRowContext(ctx, query, filterValues...)

	var t T

	err = row.Scan(r.mapScan(&t)...)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}

	return &t, nil
}

func (r PgSQLRepo[T]) FindMany(ctx context.Context, db DBContext, opts FindOptions) ([]T, error) {
	query := r.findStatement

	filterClause, filterValues, err := makeFilter(opts.Filters, r.columnNames)
	if err != nil {
		return nil, fmt.Errorf("error making filter clause: %w: %w", errkind.ErrInvalidArgument, err)
	}

	query += filterClause

	if opts.Order != nil {
		query += fmt.Sprintf(" ORDER BY %s", opts.Order.Field)

		if opts.Order.Desc {
			query += " DESC"
		}
	}

	if opts.Pagination != nil {
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", opts.Pagination.Limit, opts.Pagination.Offset)
	}

	rows, err := db.QueryContext(ctx, query, filterValues...)
	if err != nil {
		return nil, err
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("error querying rows: %w", err)
	}

	defer func() { err = rows.Close() }()

	result := make([]T, 0)

	for rows.Next() {
		var t T

		err = rows.Scan(r.mapScan(&t)...)
		if err != nil {
			return nil, err
		}

		result = append(result, t)
	}

	return result, nil
}

func (r PgSQLRepo[T]) TableName() string {
	return r.table
}

func (r PgSQLRepo[T]) Columns() []Column {
	return r.columns
}

func makeDefaultTableName[T any]() string {
	var t T
	ty := reflect.TypeOf(t)
	lowerSnakeCaseName := strings.ToLower(strcase.ToSnake(ty.Name()))
	pluralName := pluralize.NewClient().Plural(lowerSnakeCaseName)

	return pluralName
}

func makeDefaultMapScan[T any]() func(item *T) []any {
	var t T
	ty := reflect.TypeOf(t)

	return func(item *T) []any {
		scanPointers := make([]any, ty.NumField())

		for i := 0; i < ty.NumField(); i++ {
			fieldPtr := unsafe.Add(unsafe.Pointer(item), ty.Field(i).Offset)
			scanPointers[i] = reflect.NewAt(ty.Field(i).Type, fieldPtr).Interface()
		}

		return scanPointers
	}
}

func makeDefaultColumns[T any]() []Column {
	var t T
	ty := reflect.TypeOf(t)
	columns := make([]Column, 0, ty.NumField())

	for i := 0; i < ty.NumField(); i++ {
		var columnKind ColumnKind

		switch ty.Field(i).Name {
		case "ID":
			columnKind = GeneratedKeyColumn
		case "CreatedAt":
			columnKind = CreatedAtColumn
		case "UpdatedAt":
			columnKind = UpdatedAtColumn
		default:
			columnKind = ValueColumn
		}

		columns = append(columns, Column{Name: strcase.ToSnake(ty.Field(i).Name), Kind: columnKind})
	}

	return columns
}

func makeFilter(filters Filters, columnNames []string) (filterClause string, filterValues []any, err error) {
	filterClause = ""
	filterValues = make([]any, 0, len(filters))

	if len(filters) > 0 {
		placeholder := 1

		for column, value := range filters {
			if !slices.Contains(columnNames, column) {
				return "", nil, fmt.Errorf("column %s not found: %w", column, errkind.ErrInvalidArgument)
			}

			switch v := value.(type) {
			case []string:
				filterClause += fmt.Sprintf(" AND %q=ANY($%d)", column, placeholder)
				value = fmt.Sprintf("{%s}", strings.Join(v, ", "))
			default:
				filterClause += fmt.Sprintf(" AND %q=$%d", column, placeholder)
			}

			placeholder++

			filterValues = append(filterValues, value)
		}
	}

	return filterClause, filterValues, nil
}

//nolint:revive //withCreateUpdate and softDelete are legit for special cases
func makeFindStatement(table string, columns []Column, softDelete bool) string {
	joinColumns := ""

	for _, column := range columns {
		joinColumns += fmt.Sprintf("%q, ", column.Name)
	}

	joinColumns = strings.TrimSuffix(joinColumns, ", ")

	findStatement := fmt.Sprintf("SELECT %s FROM %s WHERE ", joinColumns, table)

	if softDelete {
		findStatement += "deleted_at IS NULL"
	} else {
		findStatement += "1=1"
	}

	return findStatement
}

//nolint:revive //withCreateUpdate and softDelete are legit for special cases
func makeCreateStatement(tableName string, columns []Column, withCreateUpdate bool) string {
	columnNames := ""
	createArgs := ""
	scanArgs := ""
	createArgCount := 1

	for _, column := range columns {
		switch column.Kind {
		case KeyColumn, ValueColumn:
			columnNames += fmt.Sprintf("%q, ", column.Name)
			createArgs += fmt.Sprintf(" $%d, ", createArgCount)
			scanArgs += fmt.Sprintf("%q, ", column.Name)
			createArgCount++
		case GeneratedKeyColumn, CreatedAtColumn, UpdatedAtColumn:
			scanArgs += fmt.Sprintf("%s, ", column.Name)
		}
	}

	if withCreateUpdate {
		columnNames += "created_at, updated_at"
		createArgs += " NOW(), NOW()"
	} else {
		columnNames = strings.TrimSuffix(columnNames, ", ")
		createArgs = strings.TrimSuffix(createArgs, ", ")
	}

	scanArgs = strings.TrimSuffix(scanArgs, ", ")

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) RETURNING %s", tableName, columnNames, createArgs, scanArgs)

	return query
}

//nolint:revive //withCreateUpdate and softDelete are legit for special cases
func makeUpdateOneStatement(tableName string, columns []Column, withCreateUpdate, softDelete bool) string {
	setClause := ""
	filterClause := ""

	for i, column := range columns {
		switch column.Kind {
		case GeneratedKeyColumn, KeyColumn:
			filterClause += fmt.Sprintf("%q=$%d AND ", column.Name, i+1)
		case ValueColumn:
			setClause += fmt.Sprintf("%q=$%d, ", column.Name, i+1)
		case CreatedAtColumn, UpdatedAtColumn:
		}
	}

	if withCreateUpdate {
		setClause += "updated_at = NOW()"
	}

	if softDelete {
		filterClause += "deleted_at IS NULL"
	}

	setClause = strings.TrimSuffix(setClause, ", ")
	filterClause = strings.TrimSuffix(filterClause, " AND ")

	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s", tableName, setClause, filterClause)

	return query
}

//nolint:revive //withCreateUpdate and softDelete are legit for special cases
func makeDeleteOneStatement(tableName string, columns []Column, softDelete bool) string {
	filterClause := ""
	idColumnIndex := -1

	for i, c := range columns {
		if c.Kind == GeneratedKeyColumn {
			idColumnIndex = i
		}
	}

	if idColumnIndex == -1 {
		placeholder := 1

		for _, c := range columns {
			if c.Kind == KeyColumn {
				filterClause += fmt.Sprintf("%q=$%d AND ", c.Name, placeholder)
				placeholder++
			}
		}
	} else {
		filterClause += fmt.Sprintf("%q=$1 AND ", columns[idColumnIndex].Name)
	}

	if softDelete {
		filterClause += "deleted_at IS NULL"

		return fmt.Sprintf("UPDATE %s SET deleted_at = NOW() WHERE %s", tableName, filterClause)
	} else {
		filterClause = strings.TrimSuffix(filterClause, " AND ")

		return fmt.Sprintf("DELETE FROM %s WHERE %s", tableName, filterClause)
	}
}

func makeDeleteOneScanIndices(columns []Column) []int {
	scanIndices := make([]int, 0)

	for i, c := range columns {
		if c.Kind == GeneratedKeyColumn {
			return []int{i}
		}

		if c.Kind == KeyColumn {
			scanIndices = append(scanIndices, i)
		}
	}

	return scanIndices
}
