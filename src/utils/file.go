package utils

import (
	"errors"
	"os"
	"regexp"
	"strings"
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

func IsValidFilename(filename string) bool {
	// 文件名不能为空
	if len(strings.TrimSpace(filename)) == 0 {
		return false
	}

	// 定义非法字符
	// Windows 非法字符: \ / : * ? " < > |
	// Linux 非法字符: /
	illegalChars := `[\\/:*?"<>|]`
	matched, err := regexp.MatchString(illegalChars, filename)
	if err != nil || matched {
		return false
	}

	// Windows 中不允许以空格或点结尾
	if strings.HasSuffix(filename, " ") || strings.HasSuffix(filename, ".") {
		return false
	}

	// Windows 保留文件名检查
	reservedNames := map[string]bool{
		"CON": true, "PRN": true, "AUX": true, "NUL": true,
		"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
		"COM6": true, "COM7": true, "COM8": true, "COM9": true,
		"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
		"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	}

	// 提取文件名部分（不包括扩展名）
	name := strings.Split(filename, ".")[0]
	if reservedNames[strings.ToUpper(name)] {
		return false
	}

	return true
}
