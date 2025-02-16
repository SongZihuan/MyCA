package mycav1

import (
	"fmt"
	"github.com/SongZihuan/MyCA/src/utils"
	"path"
)

func PrintMenu() {
	fmt.Println(menu)
}

func showAllRCA() []string {
	rca, err := utils.ReadDirOnlyDir(path.Join(home, "rca"))
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println("总计: ", len(rca))

	for i, v := range rca {
		fmt.Printf(" %d. %s\n", i+1, v)
	}

	return rca
}

func showAllICA() []string {
	ica, err := utils.ReadDirOnlyDir(path.Join(home, "ica"))
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println("总计: ", len(ica))

	for i, v := range ica {
		fmt.Printf(" %d. %s\n", i+1, v)
	}

	return ica
}
