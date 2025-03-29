package mycav1

import (
	"fmt"
	"github.com/SongZihuan/MyCA/src/utils"
	"golang.org/x/term"
	"os"
	"strconv"
	"strings"
	"time"
)

func ReadNumber() int {
	if stdinReader == nil {
		fmt.Println("Error: stdinReader is nil")
		return 0
	}

	input, err := stdinReader.ReadString('\n')
	if err != nil {
		fmt.Println("Error:", err)
		return 0
	}

	input = strings.TrimSuffix(input, "\n")
	input = strings.TrimSpace(input)

	if input == "" {
		return 0
	}

	m, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		fmt.Println("Error:", err)
		return 0
	}

	return int(m)
}

func ReadString() string {
	if stdinReader == nil {
		fmt.Println("Error: stdinReader is nil")
		return ""
	}

	input, err := stdinReader.ReadString('\n')
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	input = strings.TrimSuffix(input, "\n")
	input = strings.TrimSpace(input)

	return input
}

func ReadPassword() string {
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return ReadString()
	}
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), state)
		fmt.Printf("\n")
	}()

	fmt.Printf("[note: the password you type will not be echoed] ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Error:", err)
	}

	password := string(pw)
	password = strings.TrimSuffix(password, "\n")
	password = strings.TrimSpace(password)

	return password
}

func ReadTimeDuration(defaultVal time.Duration) time.Duration {
	input := ReadString()
	if input == "" {
		return defaultVal
	}

	res := utils.ReadTimeDuration(input)
	if res == 0 {
		return defaultVal
	}

	return res
}

func ReadBoolDefaultYesPrint() bool {
	fmt.Printf(" [default=yes/no] ")
	return ReadBoolDefaultYes()
}

func ReadBoolDefaultYes() bool {
	input := strings.ToLower(ReadString())
	return input != "n" && input != "no" && input != "not" && input != "stop"
}

func ReadBoolDefaultNoPrint() bool {
	fmt.Printf(" [yes/default=no] ")
	return ReadBoolDefaultNo()
}

func ReadBoolDefaultNo() bool {
	input := strings.ToLower(ReadString())
	return input == "yes" || input == "y" || input == "ok"
}
