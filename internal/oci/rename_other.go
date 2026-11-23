//go:build !linux

package oci

import "errors"

func renameNoReplace(_, _ string) error {
	return errors.New("atomic OCI export requires Linux")
}
