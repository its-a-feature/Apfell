// +build darwin

package xpc

import (
	"encoding/json"
	"fmt"
)

const (
	ALL = "__allEvents__"
)

type XpcEvent map[string]interface{}

type EventHandlerFunc func(XpcEvent) bool

type Emitter struct {
	handlers map[string]EventHandlerFunc
	event    chan XpcEvent
}

// Init initialize the emitter and start a goroutine to execute the event handlers
func (e *Emitter) Init() {
	e.handlers = make(map[string]EventHandlerFunc)
	e.event = make(chan XpcEvent)

	// event handler
	go func() {
		for {
			ev := <-e.event

			if fn, ok := e.handlers[ALL]; ok {
				if fn(ev) {
					break
				}
			} else {
				rawEvent, _ := json.MarshalIndent(ev, "", "	")
				fmt.Printf("%s", string(rawEvent))
			}
		}

		close(e.event) // TOFIX: this causes new "emits" to panic.
	}()
}

func (e *Emitter) Emit(ev XpcEvent) {
	e.event <- ev
}

func (e *Emitter) On(event string, fn EventHandlerFunc) {

}
