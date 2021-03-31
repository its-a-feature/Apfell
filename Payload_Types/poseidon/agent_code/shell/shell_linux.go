// +build linux

package shell

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/shlex"
)

//LinuxShell - struct to hold the task and result of the shell command
type LinuxShell struct {
	Task       string
	TaskResult []byte
}

//Command - interface method that returns the command
func (d *LinuxShell) Command() string {
	return d.Task
}

//Response - interface method that holds the response to the command
func (d *LinuxShell) Response() []byte {
	return d.TaskResult
}

func shellExec(c string) (Shell, error) {

	c = fmt.Sprintf("bash -c %s", c)
	args, _ := shlex.Split(c)
	cmd := exec.Command(args[0], args[1], strings.Join(args[2:], " "))

	r := &LinuxShell{}

	out, err := cmd.CombinedOutput()

	r.Task = c
	r.TaskResult = out

	if len(out) == 0 && err == nil {
		r.TaskResult = []byte("task completed")
	}

	return r, err
}
