// +build linux

package jxa

import (
	"errors"
)

type JxaRunLinux struct {
	Successful   bool
	Resultstring string
}

func (j *JxaRunLinux) Success() bool {
	return j.Successful
}

func (j *JxaRunLinux) Result() string {
	return j.Resultstring
}

func runCommand(encpayload string) (JxaRunLinux, error) {
	n := JxaRunLinux{}
	n.Resultstring = ""
	n.Successful = false
	return n, errors.New("Not implemented")
}
