package deb

import "maps"

// SignedArchive is one archive a distribution serves, with the suites, components
// and signing keys that belong to it.
//
// A provider publishes reviewed defaults so a specification that names only
// packages does not have to restate an endpoint, a suite list or a key. Keeping the
// keys beside the suites they sign is what stops one archive's key from standing in
// for another's release: a distribution that signs two archives with two keys makes
// each key evidence for its own suites only.
type SignedArchive struct {
	// Name is the repository name a lock records and a specification may declare.
	Name string
	// Endpoints is the archive's base URL per OCI platform, because one
	// distribution may publish its platforms from different hosts.
	Endpoints map[string]string
	// Suites are the suites this archive serves, all signed by Keys.
	Suites []string
	// Components are the components the archive serves.
	Components []string
	// Keys are the reviewed key snapshots that sign these suites.
	Keys []KeySnapshot
}

// Endpoint returns the URL this archive serves a platform from.
func (a *SignedArchive) Endpoint(platform string) (string, bool) {
	url, ok := a.Endpoints[platform]
	return url, ok
}

// Clone returns a copy whose slices and map the caller may keep.
func (a *SignedArchive) Clone() SignedArchive {
	cloned := SignedArchive{
		Name:       a.Name,
		Endpoints:  make(map[string]string, len(a.Endpoints)),
		Suites:     append([]string(nil), a.Suites...),
		Components: append([]string(nil), a.Components...),
	}
	maps.Copy(cloned.Endpoints, a.Endpoints)
	for i := range a.Keys {
		key := &a.Keys[i]
		cloned.Keys = append(cloned.Keys, KeySnapshot{
			Fingerprints: append([]string(nil), key.Fingerprints...),
			Data:         append([]byte(nil), key.Data...),
		})
	}
	return cloned
}
