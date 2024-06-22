package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"

	"go.mkw.re/ghidra-panel/common"
)

type DB struct {
	*sql.DB
}

func Open(filePath string) (*DB, error) {
	db, err := sql.Open("sqlite3", filePath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(migrations); err != nil {
		return nil, fmt.Errorf("migrations failed: %w", err)
	}

	return &DB{db}, nil
}

func (d *DB) GetUserState(ctx context.Context, ident *common.Identity) (*common.UserState, error) {
	hasPass := true
	username := ident.Username
	err := d.
		QueryRowContext(ctx, "SELECT username FROM passwords WHERE id = ?", ident.ID).
		Scan(&username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			hasPass = false
		} else {
			return nil, err
		}
	}
	return &common.UserState{
		Username:    username,
		HasPassword: hasPass,
	}, nil
}

func (d *DB) UsernameExists(ctx context.Context, username string) (exist bool, err error) {
	err = d.
		QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM passwords WHERE username = ?)", username).
		Scan(&exist)
	return
}

func (d *DB) CreateAccount(ctx context.Context, id uint64, username string, password string) error {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}

	// Hash password with Argon2id
	hash := argon2.IDKey([]byte(password), salt[:], 1, 19456, 2, 32)

	_, err := d.ExecContext(
		ctx,
		`INSERT INTO passwords (id, username, hash, salt, format) VALUES (?, ?, ?, ?, ?)`,
		id, username, hash, salt[:], 1,
	)
	return err
}

func (d *DB) UpdatePassword(ctx context.Context, id uint64, password string) error {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}

	// Hash password with Argon2id
	hash := argon2.IDKey([]byte(password), salt[:], 1, 19456, 2, 32)

	result, err := d.ExecContext(
		ctx,
		`UPDATE passwords SET 
			hash = ?,
			salt = ?,
			format = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		hash, salt[:], 1, id,
	)

	if err != nil {
		return err
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *DB) UpdateAccount(ctx context.Context, id uint64, username string, password string) error {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}

	// Hash password with Argon2id
	hash := argon2.IDKey([]byte(password), salt[:], 1, 19456, 2, 32)

	result, err := d.ExecContext(
		ctx,
		`UPDATE passwords SET 
			username = ?,
			hash = ?,
			salt = ?,
			format = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		username, hash, salt[:], 1, id,
	)

	if err != nil {
		return err
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *DB) SetUsername(ctx context.Context, id uint64, username string) error {
	_, err := d.ExecContext(
		ctx,
		`UPDATE passwords SET username = ? WHERE id = ?`,
		username, id,
	)
	return err
}
