package distro

import (
	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/contents"
)

// RepositoryPolicy combines provider defaults with repository declarations.
type RepositoryPolicy struct {
	Provider     Provider
	Repositories []contents.Repository
}

// PackageScope returns the names a repository was declared for, or nothing when the
// declaration granted the whole archive.
func (policy RepositoryPolicy) PackageScope(name string) []string {
	for i := range policy.Repositories {
		if policy.Repositories[i].Name == name {
			return policy.Repositories[i].Packages
		}
	}
	return nil
}

// ReleaseMatching keeps the provider's component rules even for a codename override,
// and lets a repository with its own identity name whatever release it signs.
func (policy RepositoryPolicy) ReleaseMatching(name string) deb.ReleaseIdentity {
	matching := policy.Provider.ReleaseMatching()
	for i := range policy.Repositories {
		repository := &policy.Repositories[i]
		if repository.Name != name {
			continue
		}
		if repository.SuiteMatch != nil && *repository.SuiteMatch == contents.SuiteMatchCodename {
			matching.MatchCodename = true
		}
		if repository.Identity != nil {
			matching.OwnIdentity = true
		}
		break
	}
	return matching
}
