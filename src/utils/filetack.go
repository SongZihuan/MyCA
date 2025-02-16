package utils

import (
	"encoding/gob"
	"os"
)

type FileTack[T any] struct {
	Value    T
	FilePath string
}

func NewFileTack[T any](filePath string) (*FileTack[T], error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var value T
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&value)
	if err != nil {
		return nil, err
	}

	return NewFileTackWithValue(filePath, value), nil
}

func NewFileTackWithDefault[T any](filePath string, defaultVal T) (*FileTack[T], error) {
	if !IsExists(filePath) {
		return NewFileTackWithValue(filePath, defaultVal), nil
	}

	return NewFileTack[T](filePath)
}

func NewFileTackWithValue[T any](filePath string, value T) *FileTack[T] {
	return &FileTack[T]{
		Value:    value,
		FilePath: filePath,
	}
}

func (f *FileTack[T]) Save() error {
	file, err := os.Create(f.FilePath)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	encoder := gob.NewEncoder(file)
	err = encoder.Encode(f.Value)
	if err != nil {
		return err
	}

	return nil
}
