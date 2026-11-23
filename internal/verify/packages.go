package verify

import (
	"fmt"

	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/lock"
)

type packageIdentity struct {
	repository, name, version, architecture, source string
	content                                         lock.Content
}

// payload is the identity with the source package dropped, so a selection that
// names the wrong source is told apart from one the index does not hold at all.
func (i *packageIdentity) payload() packageIdentity {
	return packageIdentity{
		repository: i.repository, name: i.name, version: i.version,
		architecture: i.architecture, content: i.content,
	}
}

type packageSelection struct {
	identity packageIdentity
	kind     string
}

// selections tracks locked selections still unaccounted for, and every payload
// the authenticated indexes did offer.
type selections struct {
	remaining map[packageIdentity]struct{}
	indexed   map[packageIdentity]struct{}
}

func newSelections(items []packageSelection) *selections {
	tracked := &selections{
		remaining: make(map[packageIdentity]struct{}, len(items)),
		indexed:   make(map[packageIdentity]struct{}),
	}
	for i := range items {
		tracked.remaining[items[i].identity] = struct{}{}
	}
	return tracked
}

func (s *selections) check(items []packageSelection) error {
	for i := range items {
		selection := &items[i]
		if _, missing := s.remaining[selection.identity]; !missing {
			continue
		}
		identity := selection.identity
		if _, found := s.indexed[identity.payload()]; found {
			return fmt.Errorf("%s %q: source %q does not match its authenticated repository index",
				selection.kind, identity.name, identity.source)
		}
		return fmt.Errorf("%s %q: payload is not present in its authenticated repository index",
			selection.kind, identity.name)
	}
	return nil
}

func (s *selections) match(repository string, candidates []deb.Package) {
	if len(s.remaining) == 0 {
		return
	}
	for i := range candidates {
		pkg := &candidates[i]
		identity := packageIdentity{
			repository: repository, name: pkg.Name, version: pkg.Version,
			architecture: pkg.Architecture, source: pkg.Source,
			content: lock.Content{Path: pkg.Filename, SHA256: pkg.SHA256, Size: pkg.Size},
		}
		s.indexed[identity.payload()] = struct{}{}
		delete(s.remaining, identity)
	}
}

func packageSelections(locked *lock.Lockfile) []packageSelection {
	items := make([]packageSelection, 0, len(locked.Packages)+len(locked.Slices))
	for i := range locked.Packages {
		pkg := &locked.Packages[i]
		items = append(items, packageSelection{kind: "package", identity: packageIdentity{
			repository: pkg.Repository, name: pkg.Name, version: pkg.Version,
			architecture: pkg.Architecture, source: pkg.Source, content: pkg.Content,
		}})
	}
	for i := range locked.Slices {
		pkg := &locked.Slices[i]
		items = append(items, packageSelection{kind: "slice", identity: packageIdentity{
			repository: pkg.Repository, name: pkg.Package, version: pkg.Version,
			architecture: pkg.Architecture, source: pkg.Source, content: pkg.Content,
		}})
	}
	return items
}
