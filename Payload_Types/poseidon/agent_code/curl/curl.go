package curl

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"pkg/profiles"
	"strings"
	"sync"
	"time"

	"pkg/utils/structs"
)

var mu sync.Mutex

type Arguments struct {
	Url     string `json:"url"`
	Method  string `json:"method"`
	Body    string `json:"body"`
	Headers string `json:"headers"`
}

//Run - Function that executes a curl command with Golang APIs
func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID
	args := &Arguments{}
	err := json.Unmarshal([]byte(task.Params), args)

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

	var body []byte
	var rawHeaders []byte

	if len(args.Body) > 0 {
		body, _ = base64.StdEncoding.DecodeString(args.Body)
	}

	if len(args.Headers) > 0 {
		rawHeaders, _ = base64.StdEncoding.DecodeString(args.Headers)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var respBody []byte
	var req *http.Request
	if len(body) > 0 {
		req, _ = http.NewRequest(args.Method, args.Url, bytes.NewBuffer(body))
	} else {
		req, _ = http.NewRequest(args.Method, args.Url, nil)
	}

	if len(rawHeaders) > 0 {
		var headers map[string]interface{}
		_ = json.Unmarshal(rawHeaders, &headers)

		for k, v := range headers {
			if strings.Contains(k, "Host") {
				req.Host = v.(string)
			} else {
				req.Header.Set(k, v.(string))
			}
		}
	}

	resp, err := client.Do(req)
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

	defer resp.Body.Close()
	respBody, err = ioutil.ReadAll(resp.Body)

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
	msg.UserOutput = string(respBody)
	r, _ := json.Marshal(msg)
	mu.Lock()
	profiles.TaskResponses = append(profiles.TaskResponses, r)
	mu.Unlock()
	return
}
