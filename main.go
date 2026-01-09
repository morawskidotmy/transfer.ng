package main

import (
	"log"
	"os"

	"github.com/morawskidotmy/transfer.ng/cmd"
)

func main() {
	app := cmd.New()
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
