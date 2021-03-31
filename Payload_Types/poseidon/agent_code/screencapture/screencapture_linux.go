// +build linux

package screencapture

import (
	"bytes"
	"errors"
	//"image"
	"image/png"

	s "github.com/kbinani/screenshot"
)

//LinuxScreenshot - struct for screenshot data
type LinuxScreenshot struct {
	MonitorIndex   int
	ScreenshotData []byte
}

//Monitor - Darwin subclass method to return the monitor index
func (d *LinuxScreenshot) Monitor() int {
	return d.MonitorIndex
}

//Data - Darwin subclass method to return the raw png data
func (d *LinuxScreenshot) Data() []byte {
	return d.ScreenshotData
}

func getscreenshot() ([]ScreenShot, error) {
	n := s.NumActiveDisplays()
	screens := make([]ScreenShot, n)
	if n <= 0 {
		return nil, errors.New("Active display not found")
	}

	//var all image.Rectangle = image.Rect(0, 0, 0, 0)

	for i := 0; i < n; i++ {
		bounds := s.GetDisplayBounds(i)
		//all = bounds.Union(all)

		img, err := s.CaptureRect(bounds)
		if err != nil {
			panic(err)
		}
		// fileName := fmt.Sprintf("%d_%dx%d.png", i, bounds.Dx(), bounds.Dy())
		// save(img, fileName)

		buf := new(bytes.Buffer)
		err = png.Encode(buf, img)

		if err != nil {
			return nil, err
		}

		screens[i] = &LinuxScreenshot{
			MonitorIndex:   i,
			ScreenshotData: buf.Bytes(),
		}
		// fmt.Printf("#%d : %v \"%s\"\n", i, bounds, fileName)
	}

	return screens, nil
}
