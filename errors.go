package goencrypt

import (
	"errors"
	"strings"
)

const runtimeErr = "runtime error:"

func handleError(err error) error {
	if strings.HasPrefix(err.Error(), runtimeErr) {
		return errors.New("encrypted and decrypted passwords are inconsistent")
	}
	return err
}
