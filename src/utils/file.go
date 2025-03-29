package utils

import (
	"errors"
	"os"
)

func IsExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func IsFile(path string) bool {
	stat, err := os.Stat(path)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false
	} else if stat.IsDir() {
		return false
	}
	return true
}

func IsDir(path string) bool {
	stat, err := os.Stat(path)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false
	} else if stat.IsDir() {
		return true
	}
	return false
}

func ReadDir(dirPath string) ([]string, error) {
	entry, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	res := make([]string, 0, len(entry))

	for _, e := range entry {
		res = append(res, e.Name())
	}

	return res, nil
}

func ReadDirOnlyFile(dirPath string) ([]string, error) {
	entry, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	res := make([]string, 0, len(entry))

	for _, e := range entry {
		if e.IsDir() {
			continue
		}

		res = append(res, e.Name())
	}

	return res, nil
}

func ReadDirOnlyDir(dirPath string) ([]string, error) {
	entry, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	res := make([]string, 0, len(entry))

	for _, e := range entry {
		if !e.IsDir() {
			continue
		}

		res = append(res, e.Name())
	}

	return res, nil
}
