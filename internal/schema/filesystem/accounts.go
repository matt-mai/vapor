// Package filesystem defines image paths, accounts, and CA bundle declarations.
package filesystem

import (
	"errors"
	"fmt"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
)

func validateAccounts(accounts Accounts) error {
	if err := validateGroups(accounts.Groups); err != nil {
		return err
	}
	names, ids := make(map[string]bool), make(map[int]bool)
	for i := range accounts.Users {
		user := &accounts.Users[i]
		if err := validateUserAccount(*user); err != nil {
			return fmt.Errorf("filesystem.accounts.users[%d]: %w", i, err)
		}
		if names[user.Name] || ids[*user.UID] {
			return errors.New("duplicate user name or uid")
		}
		names[user.Name], ids[*user.UID] = true, true
	}
	return nil
}

func validateGroups(groups []GroupAccount) error {
	names, ids := make(map[string]bool), make(map[int]bool)
	for i, group := range groups {
		if err := base.RequirePattern("group name", group.Name, `^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`); err != nil {
			return fmt.Errorf("filesystem.accounts.groups[%d]: %w", i, err)
		}
		if err := validateIDs(group.GID); err != nil {
			return fmt.Errorf("filesystem.accounts.groups[%d]: %w", i, err)
		}
		if names[group.Name] || ids[*group.GID] {
			return errors.New("duplicate group name or gid")
		}
		names[group.Name], ids[*group.GID] = true, true
	}
	return nil
}

func validateUserAccount(user UserAccount) error {
	if err := base.RequirePattern("user name", user.Name, `^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`); err != nil {
		return err
	}
	if err := validateIDs(user.UID, user.GID); err != nil {
		return err
	}
	if user.Home == nil || user.Shell == nil {
		return errors.New("user requires defaulted home and shell")
	}
	if err := ValidateImagePath(*user.Home, true); err != nil {
		return fmt.Errorf("user home: %w", err)
	}
	if err := ValidateImagePath(*user.Shell, false); err != nil {
		return fmt.Errorf("user shell: %w", err)
	}
	if strings.ContainsAny(*user.Home+*user.Shell, ":") {
		return errors.New("account fields must not contain colons")
	}
	return nil
}
