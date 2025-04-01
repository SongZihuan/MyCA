package mycav1

import (
	"fmt"
	"github.com/SongZihuan/MyCA/src/utils"
	"os"
	"path"
)

func PrintMenu() {
	fmt.Println(menu)
}

func showAllRCA() []string {
	rca, err := utils.ReadDirOnlyDir(path.Join(home, "rca"))
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
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
		fmt.Printf("Error: %s\n", err.Error())
	}

	fmt.Println("总计: ", len(ica))

	for i, v := range ica {
		fmt.Printf(" %d. %s\n", i+1, v)
	}

	return ica
}

func showFileOnPath(basePath string) []os.DirEntry {
	fileList, err := os.ReadDir(basePath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}

	fmt.Printf("地址 %s 下文件列表 总计: %d\n", basePath, len(fileList))

	var dirCount = 0
	var fileCount = 0

	for i, v := range fileList {
		if v.IsDir() {
			fmt.Printf(" %d. 文件夹 %s\n", i+1, v.Name())
			dirCount += 1
		} else {
			fmt.Printf(" %d. 文件 %s\n", i+1, v.Name())
			fileCount += 1
		}
	}

	if fileCount+dirCount != len(fileList) {
		panic("file count add dir count not equal the total count")
	}

	fmt.Printf("文件：%d 文件夹：%d  总计：%d\n", fileCount, dirCount, len(fileList))

	return fileList
}
