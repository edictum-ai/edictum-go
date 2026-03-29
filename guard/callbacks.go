package guard

import (
	"log"

	"github.com/edictum-ai/edictum-go/toolcall"
)

// fireOnBlock invokes the on_block callback, swallowing panics.
func (g *Guard) fireOnBlock(env2 toolcall.ToolCall, reason, name string) {
	if g.onBlock == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("on_block callback panicked: %v", r)
		}
	}()
	g.onBlock(env2, reason, name)
}

// fireOnAllow invokes the on_allow callback, swallowing panics.
func (g *Guard) fireOnAllow(env2 toolcall.ToolCall) {
	if g.onAllow == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("on_allow callback panicked: %v", r)
		}
	}()
	g.onAllow(env2)
}

// fireOnPostWarn invokes the on_post_warn callback, swallowing panics.
func (g *Guard) fireOnPostWarn(env2 toolcall.ToolCall, warnings []string) {
	if g.onPostWarn == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("on_post_warn callback panicked: %v", r)
		}
	}()
	g.onPostWarn(env2, warnings)
}
