// +build darwin

package functions

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation
#include "foundation_darwin.h"
*/
import "C"
import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"unicode/utf16"
)

func cstring(s *C.NSString) *C.char { return C.nsstring2cstring(s) }
func gostring(s *C.NSString) string { return C.GoString(cstring(s)) }
func isElevated() bool {
	currentUser, _ := user.Current()
	return currentUser.Uid == "0"
}
func getArchitecture() string {
	return runtime.GOARCH
}
func getDomain() string {
	host, _ := os.Hostname()
	return host
}
func getOS() string {
	return gostring(C.GetOSVersion())
	//return runtime.GOOS
}

// Helper function to convert DWORD byte counts to
// human readable sizes.
func UINT32ByteCountDecimal(b uint32) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint32(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float32(b)/float32(div), "kMGTPE"[exp])
}

// Helper function to convert LARGE_INTEGER byte
//  counts to human readable sizes.
func UINT64ByteCountDecimal(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

// Helper function to build a string from a WCHAR string
func UTF16ToString(s []uint16) []string {
	var results []string
	cut := 0
	for i, v := range s {
		if v == 0 {
			if i-cut > 0 {
				results = append(results, string(utf16.Decode(s[cut:i])))
			}
			cut = i + 1
		}
	}
	if cut < len(s) {
		results = append(results, string(utf16.Decode(s[cut:])))
	}
	return results
}
