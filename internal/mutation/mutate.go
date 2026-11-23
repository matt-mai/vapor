package mutation

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/matt-mai/vapor/internal/vfs"
)

// Request is one script to run against a committed image tree.
type Request struct {
	// Name identifies the script in failures, for example "fixture/mutate".
	Name string
	// Script is the source text.
	Script []byte
	// MaxSteps is the interpreter step budget for this script.
	MaxSteps int
	// Abort makes the script's worker die without replying, so a caller can prove
	// an abruptly killed worker commits nothing. Only a test sets it.
	Abort bool
	// Hang makes the script's worker block before evaluating, so a caller can prove
	// the wall clock and cancellation stop a worker the interpreter never sees.
	// Only a test sets it.
	Hang bool
}

// Result reports what a successful mutation run did.
type Result struct {
	// Steps is the total interpreter steps used by all scripts.
	Steps uint64
	// Scripts is the number of scripts that ran.
	Scripts int
}

// Mutate runs scripts against tree in order, committing only if every script
// succeeds. mutable lists the paths a script may write; every other path in the
// image is readable but immutable. A failure of any kind leaves tree exactly as it was: scripts are
// staged against a copy, so there is no partial application to undo.
//
// Each script gets a fresh worker, so one script's memory and CPU are not charged
// to the next. The cumulative growth bound is build-wide and checked before each
// commit.
func Mutate(ctx context.Context, tree *vfs.Tree, mutable []string, requests []Request, limits SandboxLimits) (*Result, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if err := SandboxSupported(); err != nil {
		return nil, err
	}
	if tree == nil {
		return nil, errors.New("mutation requires an image tree")
	}
	staged := tree.Clone()
	writable := sortedCopy(mutable)
	hardLinks := hardLinkPaths(staged)
	result := &Result{}
	growth := &growthBudget{limit: limits.MaxVFSGrowthBytes}
	for _, request := range requests {
		payload := &ScriptRequest{
			Script:    request.Script,
			MaxSteps:  request.MaxSteps,
			Mutable:   writable,
			HardLinks: hardLinks,
			Abort:     request.Abort,
			Hang:      request.Hang,
		}
		indexTree(staged, payload)
		scriptResult, err := runScript(ctx, payload, &limits, staged.OpenFile)
		if err != nil {
			return nil, scriptFailure(request.Name, err)
		}
		if err := applyScriptResult(staged, scriptResult.Writes, growth); err != nil {
			return nil, scriptFailure(request.Name, err)
		}
		result.Steps += scriptResult.Steps
		result.Scripts++
	}
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	if err := tree.Replace(staged); err != nil {
		return nil, err
	}
	return result, nil
}

// sortedCopy returns a sorted copy so the request is deterministic and the caller's
// slice is never shared with a worker.
func sortedCopy(values []string) []string {
	paths := make([]string, len(values))
	copy(paths, values)
	sort.Strings(paths)
	return paths
}

// hardLinkPaths lists paths that share an inode with another path. A write to one
// would change the other, so the content API refuses them.
func hardLinkPaths(tree *vfs.Tree) []string {
	inodes := tree.Inodes()
	owners := make(map[uint64]int, len(inodes))
	for _, id := range inodes {
		owners[id]++
	}
	paths := make([]string, 0, len(inodes))
	for name, id := range inodes {
		if owners[id] > 1 {
			paths = append(paths, name)
		}
	}
	sort.Strings(paths)
	return paths
}

func indexTree(tree *vfs.Tree, request *ScriptRequest) {
	request.Links = make(map[string]string)
	for _, entry := range tree.Entries() {
		switch entry.Kind {
		case vfs.File:
			request.FileIndex = append(request.FileIndex, fileMetadata{Name: entry.Path, Size: entry.Size})
		case vfs.Dir:
			request.Dirs = append(request.Dirs, entry.Path)
		case vfs.Symlink:
			request.Links[entry.Path] = entry.Target
		}
	}
}

func applyScriptResult(tree *vfs.Tree, writes map[string][]byte, growth *growthBudget) error {
	names := make([]string, 0, len(writes))
	for name := range writes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, ok := tree.Lookup(name)
		if !ok || entry.Kind != vfs.File {
			return &ScriptError{Kind: FailureCapability, Message: "worker wrote a path that is not a regular image file"}
		}
		data := writes[name]
		if err := growth.charge(int64(len(data)) - entry.Size); err != nil {
			return err
		}
		if err := tree.ReplaceFile(name, data); err != nil {
			return err
		}
	}
	return nil
}

// growthBudget tracks bytes added across the whole run, so scripts that each stay
// under their own bound cannot exceed the build-wide bound together.
type growthBudget struct {
	limit int64
	used  int64
}

func (b *growthBudget) charge(delta int64) error {
	if delta <= 0 {
		return nil
	}
	if b.used+delta > b.limit {
		return &ScriptError{Kind: FailureVFSGrowth, Message: "mutation exceeds the build growth bound"}
	}
	b.used += delta
	return nil
}

// scriptFailure names the script that failed so a build reports which one, without
// exposing worker internals.
func scriptFailure(name string, err error) error {
	if scriptErr, ok := errors.AsType[*ScriptError](err); ok {
		return &ScriptError{Kind: scriptErr.Kind, Message: fmt.Sprintf("%s: %s", name, scriptErr.Message)}
	}
	return fmt.Errorf("mutation script %q failed: %w", name, err)
}
