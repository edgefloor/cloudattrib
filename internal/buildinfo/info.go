// Package buildinfo reads source-control metadata embedded by the Go tool.
package buildinfo

import "runtime/debug"

// DirtyState reports whether tracked source files differed from the recorded
// revision at build time.
type DirtyState string

// DirtyState values describe the tracked source tree at build time.
const (
	Clean        DirtyState = "clean"
	Dirty        DirtyState = "dirty"
	DirtyUnknown DirtyState = "unknown"
)

// Info is the source-control identity embedded in one Go binary.
type Info struct {
	Revision      string     `json:"revision,omitempty"`
	RevisionKnown bool       `json:"revision_known"`
	Dirty         DirtyState `json:"dirty"`
}

// Current returns embedded VCS metadata with explicit unknown values.
func Current() Info {
	information, ok := debug.ReadBuildInfo()
	if !ok {
		return Info{Dirty: DirtyUnknown}
	}
	return fromSettings(information.Settings)
}

func fromSettings(settings []debug.BuildSetting) Info {
	result := Info{Dirty: DirtyUnknown}
	for _, setting := range settings {
		switch setting.Key {
		case "vcs.revision":
			if setting.Value != "" {
				result.Revision = setting.Value
				result.RevisionKnown = true
			}
		case "vcs.modified":
			switch setting.Value {
			case "true":
				result.Dirty = Dirty
			case "false":
				result.Dirty = Clean
			}
		}
	}
	return result
}
