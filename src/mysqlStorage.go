package main

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

const mysqlSchema = `
  create table if not exists storage (
    name varchar(255) primary key,
    value blob not null,
    mtime int not null
  )
`

const mysqlLockPrefix = "__locks/"
const mysqlQueryTimeout = 15 * time.Second
const mysqlLockPollInterval = 2 * time.Second
const mysqlLockRefreshInterval = 5 * time.Second
const mysqlLockStaleCutoff = 3 * mysqlLockRefreshInterval

type MysqlStorage struct {
	db *sql.DB
}

func NewMysqlStorage(ctx context.Context, dsn string) (*MysqlStorage, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(30 * time.Second)

	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	if _, err := db.ExecContext(ctxT, mysqlSchema); err != nil {
		return nil, err
	}

	return &MysqlStorage{db}, nil
}

func (storage *MysqlStorage) removeStaleLocks(ctx context.Context) error {
	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	cutoff := time.Now().Add(-1 * mysqlLockStaleCutoff).Unix()
	result, err := storage.db.ExecContext(ctxT,
		"delete from storage where name like ? and mtime < ?",
		mysqlLockPrefix+"%", cutoff,
	)
	if err != nil {
		return err
	}
	num, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if num > 0 {
		log.Info("removed stale locks", zap.Int64("num", num))
	}
	return err
}

func (storage *MysqlStorage) tryLock(ctx context.Context, name string, requestId string) (bool, error) {
	storage.removeStaleLocks(ctx)

	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	mtime := time.Now().Unix()
	_, err := storage.db.ExecContext(ctxT,
		"insert into storage (name, value, mtime) values (?, ?, ?)",
		mysqlLockPrefix+name, requestId, mtime,
	)
	var merr *mysql.MySQLError
	if errors.As(err, &merr) && merr.Number == 1062 {
		return false, nil
	}
	return err == nil, err
}

func (storage *MysqlStorage) keepFresh(ctx context.Context, name string, requestId string) {
	ticker := time.Tick(mysqlLockRefreshInterval)
	for mtime := range ticker {
		ok, err := storage.updateLock(ctx, name, requestId, mtime.Unix())
		if err != nil {
			log.Error("could not update lock", zap.String("name", name), zap.Error(err))
		}
		if !ok {
			break
		}
	}
}

func (storage *MysqlStorage) updateLock(ctx context.Context, name string, requestId string, mtime int64) (bool, error) {
	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	result, err := storage.db.ExecContext(ctxT,
		"update storage set mtime = ? where name = ? and value = ?",
		mtime, mysqlLockPrefix+name, requestId,
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (storage *MysqlStorage) Lock(ctx context.Context, name string) error {
	requestId := makeLockRequestId()
	for {
		ok, err := storage.tryLock(ctx, name, requestId)
		if err != nil {
			return err
		}
		if ok {
			break
		}
		time.Sleep(mysqlLockPollInterval)
	}
	go storage.keepFresh(context.Background(), name, requestId)
	return nil
}

func (storage *MysqlStorage) Unlock(ctx context.Context, name string) error {
	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	_, err := storage.db.ExecContext(ctxT,
		"delete from storage where name = ?",
		mysqlLockPrefix+name,
	)
	return err
}

func (storage *MysqlStorage) Store(ctx context.Context, key string, value []byte) error {
	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	mtime := time.Now().Unix()
	_, err := storage.db.ExecContext(ctxT,
		"insert into storage (name, value, mtime) values (?, ?, ?) "+
			"on duplicate key update value = ?, mtime = ?",
		key, value, mtime, value, mtime,
	)
	return err
}

func (storage *MysqlStorage) Load(ctx context.Context, key string) ([]byte, error) {
	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	var value []byte
	err := storage.db.QueryRowContext(ctxT,
		"select value from storage where name = ?",
		key,
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		err = fs.ErrNotExist
	}
	return value, err
}

func (storage *MysqlStorage) Delete(ctx context.Context, key string) error {
	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	_, err := storage.db.ExecContext(ctxT,
		"delete from storage where name = ?",
		key,
	)
	return err
}

func (storage *MysqlStorage) Exists(ctx context.Context, key string) bool {
	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	var ok bool
	storage.db.QueryRowContext(ctxT,
		"select true from storage where name = ?",
		key,
	).Scan(&ok)
	return ok
}

func (storage *MysqlStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	var rows *sql.Rows
	var err error
	if recursive {
		rows, err = storage.db.QueryContext(ctxT,
			"select name from storage where name like ?",
			path+"%",
		)
	} else {
		rows, err = storage.db.QueryContext(ctxT,
			"select name from storage where name like ? and name not like ?",
			path+"%", path+"%/%",
		)
	}
	if err != nil {
		return nil, err
	}

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}

	return names, err
}

func (storage *MysqlStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	ctxT, cancel := context.WithTimeout(ctx, mysqlQueryTimeout)
	defer cancel()
	info := certmagic.KeyInfo{Key: key}
	var mtime int64
	err := storage.db.QueryRowContext(ctxT,
		"select length(value), mtime from storage where name = ?",
		key,
	).Scan(&info.Size, &mtime)
	if errors.Is(err, sql.ErrNoRows) {
		err = fs.ErrNotExist
	}
	if err != nil {
		info.Modified = time.Unix(mtime, 0)
	}
	return info, err
}

// Interface guard
var _ certmagic.Storage = (*MysqlStorage)(nil)
