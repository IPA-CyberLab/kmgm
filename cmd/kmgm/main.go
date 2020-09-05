package main

import (
	"errors"
	"os"

	"go.uber.org/zap"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/app"
)

type ExitCoder interface {
	ExitCode() int
}

func ExitCodeOfError(err error) int {
	for {
		if ec, ok := err.(ExitCoder); ok {
			return ec.ExitCode()
		}

		if err = errors.Unwrap(err); err == nil {
			break
		}
	}

	return 1
}

func main() {
	if err := app.New().Run(os.Args); err != nil {
		// omit stacktrace
		zap.L().WithOptions(zap.AddStacktrace(zap.FatalLevel)).Error(err.Error())
		os.Exit(ExitCodeOfError(err))
	}
}
