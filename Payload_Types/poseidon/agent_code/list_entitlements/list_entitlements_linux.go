// +build linux

package list_entitlements

type LinuxListEntitlements struct {
	Successful bool
	Message    string
	CodeSign   int
}

func listEntitlements(pid int) (LinuxListEntitlements, error) {
	res := LinuxListEntitlements{}
	res.Successful = false
	res.Message = "Not Supported"
	return res, nil
}
func listCodeSign(pid int) (LinuxListEntitlements, error) {
	res := LinuxListEntitlements{}
	res.Successful = false
	res.Message = "Not Supported"
	res.CodeSign = -1
	return res, nil
}
