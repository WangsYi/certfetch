package db

import (
	"errors"
	"log"
	"strconv"

	"github.com/syndtr/goleveldb/leveldb"
)

func GetProcess(name string) (int64, error) {
	data, err := DB.Get([]byte(name), nil)

	if errors.Is(err, leveldb.ErrNotFound) {
		return 0, nil
	}

	if err != nil {
		log.Println("Error while getting process:", err, "return -1")
		return -1, err
	}
	idx, err := strconv.ParseInt(string(data), 10, 64)

	if err != nil {
		log.Println("Error while parsing process:", err, "return -1")
		return -1, err
	}

	return idx, nil
}

func SetProcess(name string, idx int64) error {
	err := DB.Put([]byte(name), []byte(strconv.FormatInt(idx, 10)), nil)
	if err != nil {
		return err
	}

	return nil
}
