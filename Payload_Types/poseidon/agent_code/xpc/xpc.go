package xpc

import (
	"encoding/json"
	"pkg/profiles"
	"pkg/utils/structs"
	"sync"
)

var mu sync.Mutex
var results json.RawMessage
var args Arguments

type Arguments struct {
	Command     string `json:"command"`
	ServiceName string `json:"servicename"`
	Program     string `json:"program"`
	File        string `json:"file"`
	KeepAlive   bool   `json:"keepalive"`
	Pid         int    `json:"pid"`
	Data        string `json:"data"`
}

func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID
	args = Arguments{}
	err := json.Unmarshal([]byte(task.Params), &args)

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

	res, err := runCommand(args.Command)

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

	msg.UserOutput = string(res)
	msg.Completed = true

	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
