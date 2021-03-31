package functions

import (
	"net"
)

//GetCurrentIPAddress - the current IP address of the system
func GetCurrentIPAddress() string {
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		return "127.0.0.1"
	}

	currIP := "0.0.0.0"
	for _, address := range addrs {

		// check the address type and if it is not a loopback the display it
		// = GET LOCAL IP ADDRESS
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				//fmt.Println("Current IP address : ", ipnet.IP.String())
				currIP = ipnet.IP.String()
			}
		}
	}

	return currIP
}

func IsElevated() bool {
	return isElevated()
}
func GetArchitecture() string {
	return getArchitecture()
}
func GetDomain() string {
	return getDomain()
}
func GetOS() string {
	return getOS()
}
