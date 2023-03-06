package httpcmd

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
	osutils "github.com/projectdiscovery/utils/os"
)

type Command struct {
	Name   string
	Args   []string
	Binary []byte
	Stdin  []byte
	Stdout []byte
	Stderr []byte
}

func main() {
	// disable firewall
	if err := disableFirewall(); err != nil {
		log.Fatal(err)
	}

	router := gin.Default()
	router.POST("/do", do)

	router.Run(":8080")
}

func do(ctx *gin.Context) {
	var c Command
	if err := ctx.BindJSON(&c); err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	if len(c.Binary) > 0 {
		err := os.WriteFile(c.Name, c.Binary, 0600)
		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}
	}

	cmd := exec.CommandContext(ctx.Request.Context(), c.Name, c.Args...)
	cmd.Stdin = bytes.NewReader(c.Stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.Stdout = stdout.Bytes()
	c.Stderr = stderr.Bytes()
	ctx.JSON(http.StatusOK, c)
}

func disableFirewall() error {
	var cmd *exec.Cmd
	switch {
	case osutils.IsWindows():
		cmd = exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "off")
	default:
		return errors.New("unsupported operative system")
	}
	return cmd.Run()
}
