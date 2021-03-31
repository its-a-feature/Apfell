// +build darwin

package list_entitlements

/*
#cgo LDFLAGS: -lm -framework Foundation
#cgo CFLAGS: -Wno-error=implicit-function-declaration
#include "list_entitlements_darwin.h"
*/
import "C"

type DarwinListEntitlements struct {
	Successful bool
	Message    string
	CodeSign   int
}

func listEntitlements(pid int) (DarwinListEntitlements, error) {
	res := DarwinListEntitlements{}
	i := C.int(pid)
	r := C.exec_csops(i)
	res.Successful = true
	res.Message = C.GoString(r)
	if len(res.Message) == 0 {
		res.Successful = false
	}
	return res, nil
}
func listCodeSign(pid int) (DarwinListEntitlements, error) {
	res := DarwinListEntitlements{}
	i := C.int(pid)
	r := C.exec_csops_status(i)
	res.Successful = true
	res.CodeSign = int(r)
	if r == -1 {
		res.Successful = false
	}
	return res, nil
}
