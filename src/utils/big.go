package utils

import (
	"math/big"
)

func WriteBigIntToFile(filename string, value *big.Int) error {
	f := NewFileTackWithValue(filename, value)
	err := f.Save()
	if err != nil {
		return err
	}

	return nil
}

func ReadBigIntFromFile(filepath string) (*big.Int, error) {
	f, err := ReadBigIntFromFileWithFileStack(filepath)
	if err != nil {
		return nil, err
	}

	return f.Value, nil
}

func ReadBigIntFromFileWithFileStack(filepath string) (*FileTack[*big.Int], error) {
	return NewFileTackWithDefault[*big.Int](filepath, big.NewInt(0))
}
