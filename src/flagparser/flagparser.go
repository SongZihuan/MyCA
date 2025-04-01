package flagparser

import (
	"flag"
	"fmt"
	resource "github.com/SongZihuan/MyCA"
	"os/user"
	"path"
)

var help bool
var version bool
var Home string

var StopRun = fmt.Errorf("stop run")

func InitFlagParser() error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	flag.BoolVar(&help, "help", false, "show help")
	flag.BoolVar(&help, "h", false, "show help")
	flag.BoolVar(&version, "version", false, "show version")
	flag.BoolVar(&version, "v", false, "show version")
	flag.StringVar(&Home, "home", path.Join(currentUser.HomeDir, ".myca"), "set home directory")

	flag.Parse()

	if help {
		flag.Usage()
		return StopRun
	}

	if version {
		fmt.Println("Version: ", resource.Version)
		return StopRun
	}

	return nil
}
