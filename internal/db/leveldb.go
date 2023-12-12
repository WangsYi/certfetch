package db

import (
	"log"

	"github.com/syndtr/goleveldb/leveldb"
)

var DB *leveldb.DB

func InitDB() {
	ldb, err := leveldb.OpenFile("./data/db/", nil)
	if err != nil {
		log.Fatalf("Couldn't open db: %v", err)
	}
	DB = ldb
}
