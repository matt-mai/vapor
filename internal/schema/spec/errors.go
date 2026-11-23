package spec

// inputError preserves a library cause without echoing potentially secret inputs.
type inputError struct {
	message string
	cause   error
}

func (e *inputError) Error() string { return e.message }
func (e *inputError) Unwrap() error { return e.cause }
