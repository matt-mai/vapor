package lock

import (
	"slices"
	"strings"
	"testing"
)

func TestVerifyLockfile_ArchiveRepositoryBinding(t *testing.T) {
	t.Parallel()
	spec, lock := validMultiPlatformLock(t)
	other := spec.Contents.Repositories[0]
	other.Name = "other"
	other.Endpoints = slices.Clone(other.Endpoints)
	other.Endpoints[0].URL = "https://other.example.com/ubuntu"
	spec.Contents.Repositories = append(spec.Contents.Repositories, other)
	for i := range lock.Slices {
		repository := lock.Repositories[i]
		repository.Name = "other"
		repository.URL = other.Endpoints[i].URL
		repository.ID = RepositoryID(repository.Name, repository.Platform, repository.Architecture, repository.URL, repository.Suite)
		lock.Repositories = append(lock.Repositories, repository)
		lock.Slices[i].Repository = repository.ID
	}
	for _, bound := range []string{"other", "main"} {
		spec.Contents.Catalogues[0].Archives["ubuntu"] = bound
		var err error
		lock.SpecDigest, err = spec.SpecDigest()
		if err != nil {
			t.Fatal(err)
		}
		defaults := bindingDefaults()
		for platform := range defaults.Bindings {
			binding := defaults.Bindings[platform]
			binding.Repository = bound
			defaults.Bindings[platform] = binding
		}
		err = VerifyLockfileForProvider(spec, lock, spec.Release, defaults)
		if bound == "other" {
			if err != nil {
				t.Fatalf("matching archive binding: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "archive binding") {
			t.Fatalf("mismatched binding: %v", err)
		}
	}
}

func TestVerifyLockfile_ReleasePaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		format    string
		path      string
		signature string
		valid     bool
	}{
		{"inrelease", "inrelease", "dists/resolute/InRelease", "", true},
		{"detached", "release-gpg", "dists/resolute/Release", "dists/resolute/Release.gpg", true},
		{"wrong suite", "inrelease", "dists/jammy/InRelease", "", false},
		{"wrong format basename", "inrelease", "dists/resolute/Release", "", false},
		{"wrong detached basename", "release-gpg", "dists/resolute/InRelease", "dists/resolute/Release.gpg", false},
		{"wrong signature suite", "release-gpg", "dists/resolute/Release", "dists/jammy/Release.gpg", false},
		{"wrong signature basename", "release-gpg", "dists/resolute/Release", "dists/resolute/unrelated.sig", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, lock := validMultiPlatformLock(t)
			release := &lock.Repositories[0].Release
			release.Format, release.Path = tt.format, tt.path
			if tt.signature != "" {
				release.Signature = &Content{Path: tt.signature, SHA256: strings.Repeat("a", 64), Size: 10}
			}
			err := VerifyLockfileForProvider(spec, lock, spec.Release, bindingDefaults())
			if tt.valid && err != nil {
				t.Fatalf("valid release rejected: %v", err)
			}
			if !tt.valid && (err == nil || !strings.Contains(err.Error(), "release")) {
				t.Fatalf("invalid release path: %v", err)
			}
		})
	}
}

func TestVerifyLockfile_EmptyArtifact(t *testing.T) {
	t.Parallel()
	spec, lock := validMultiPlatformLock(t)
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	spec.Contents.Artifacts[0].Sources[0].SHA256 = emptySHA256
	lock.Artifacts[0].SHA256, lock.Artifacts[0].Size = emptySHA256, 0
	var err error
	lock.SpecDigest, err = spec.SpecDigest()
	if err != nil {
		t.Fatal(err)
	}
	for _, encode := range []func() ([]byte, error){lock.CanonicalJSON, lock.CanonicalYAML} {
		data, err := encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeLockfile(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyLockfileForProvider(spec, decoded, spec.Release, bindingDefaults()); err != nil {
			t.Fatalf("valid empty artifact rejected: %v", err)
		}
	}
}
