package httperr

type ErrorWithStatusCode struct {
	StatusCode int
	Err        error
}

func (e ErrorWithStatusCode) Error() string {
	return e.Err.Error()
}

func (e ErrorWithStatusCode) GetStatusCode() int {
	return e.StatusCode
}

func (e ErrorWithStatusCode) Unwrap() error {
	return e.Err
}

func StatusCodeFromError(e interface{}) int {
	if statusCoder, ok := e.(interface {
		GetStatusCode() int
	}); ok {
		return statusCoder.GetStatusCode()
	}

	return 500
}
