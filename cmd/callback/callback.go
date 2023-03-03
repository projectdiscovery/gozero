package callback

import (
	"bytes"
	"context"
	"flag"
	"log"
	"os"
	"os/exec"
)

func main() {
	input := flag.String("stdin", "", "stdin")
	output := flag.String("stdout", "", "stdout")
	flag.Parse()
	cmdWithArgs := flag.Args()
	cmd := exec.CommandContext(context.Background(), cmdWithArgs[0], cmdWithArgs[1:]...)

	stdin, err := os.Open(*input)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer stdin.Close()

	var stdout, stderr bytes.Buffer
	cmd.Stdin = stdin
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	os.WriteFile(*output, stderr.Bytes(), 0600)
}
