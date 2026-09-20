// Package example demonstrates concise Go API documentation.
package example

import "errors"

// ErrNotFound is returned when a requested item does not exist.
var ErrNotFound = errors.New("example: not found")

// MaxRetries is the default number of retry attempts.
const MaxRetries = 3

// Widget requires construction through NewWidget; call Close to release resources.
type Widget struct {
	name string
}

// NewWidget requires a non-empty name and panics otherwise.
func NewWidget(name string) *Widget {
	if name == "" {
		panic("example: name must be non-empty")
	}
	return &Widget{name: name}
}

// Process returns ErrNotFound for references to missing items.
func (w *Widget) Process(input string) (string, error) {
	return input, nil
}

// Close releases resources held by the Widget.
func (w *Widget) Close() error {
	return nil
}

// Deprecated: Use [NewWidget] with functional options instead.
func NewWidgetLegacy(name string) *Widget {
	return NewWidget(name)
}
