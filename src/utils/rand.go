package utils

import (
	"math/rand"
	"time"
)

var _rander *rand.Rand = nil

func init() {
	_rander = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func Rander() *rand.Rand {
	if _rander == nil {
		panic("nil rander")
	}

	return _rander
}

func RandIntn(n int) int {
	if n <= 0 {
		return 0
	}

	return _rander.Intn(n)
}
