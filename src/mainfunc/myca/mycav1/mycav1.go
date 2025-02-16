package mycav1

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/SongZihuan/MyCA/src/flagparser"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func MainV1() (exitcode int) {
	err := flagparser.InitFlagParser()
	if err != nil {
		if errors.Is(err, flagparser.StopRun) {
			return 0
		}

		fmt.Println("Error:", err)
		return 1
	}

	home = flagparser.Home
	stdinReader = bufio.NewReader(os.Stdin)

	stopChan := make(chan int, 2)
	sigChan := make(chan os.Signal, 10)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Welcome to MyCA")
	fmt.Println("Home Directory: ", home)

	go MainCycle(stopChan)

	select {
	case exitcode = <-stopChan:
		return exitcode
	case <-sigChan:
		return 0
	}
}

func MainCycle(stopchan chan int) {
MainCycle:
	for {
		res := func() bool {
			PrintMenu()
			fmt.Printf("%s >>> ", time.Now().Format("15:04:05"))

			m := ReadNumber()

			switch m {
			case 0:
				// pass
			case 1:
				ShowAllRCA()
			case 2:
				ShowAllICA()
			case 3:
				CreateRCA()
			case 4:
				CreateICAFromRCA()
			case 5:
				CreateICAFromICA()
			case 6:
				CreateUserCertFromRCA()
			case 7:
				CreateUserCertFromICA()
			case 8:
				CreateUserCertSelf()
			case 9:
				stopchan <- 0
				close(stopchan)
				return false
			default:
				fmt.Println("Error: Unknown Command")
			}

			fmt.Printf("\n")
			return true
		}()
		if !res {
			break MainCycle
		}
	}
}
