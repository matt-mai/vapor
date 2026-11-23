// Package lockinput acquires catalogue, repository, package and artifact evidence for lock assembly.
package lockinput

import (
	"context"
	"fmt"

	"github.com/matt-mai/vapor/internal/acquire"
	"github.com/matt-mai/vapor/internal/distro/deb"
	"github.com/matt-mai/vapor/internal/schema/contents"
	"github.com/matt-mai/vapor/internal/schema/lock"
	"github.com/matt-mai/vapor/internal/snapshot"
	"github.com/matt-mai/vapor/internal/vfs"
)

// acquireArtifacts locks every artifact payload and returns, beside the records, the
// local packages it checked. The caller holds the selected whole packages, so the
// dependency check runs there rather than against the local packages alone.
func acquireArtifacts(ctx context.Context, request *Request) ([]lock.Artifact, []packageArtifact, error) {
	records, err := acquire.Artifacts(ctx, request.Artifacts, snapshot.NewLocal(request.SpecDir), request.Cache,
		request.Spec.Contents.Artifacts, request.Spec.Platforms, request.Progress)
	if err != nil {
		return nil, nil, err
	}
	packages := make([]packageArtifact, 0, len(records))
	result := make([]lock.Artifact, 0, len(records))
	for i := range records {
		record := &records[i]
		if record.Unpack == contents.ArtifactUnpackPackage {
			checked, err := checkArtifactPackage(record, request)
			if err != nil {
				return nil, nil, err
			}
			packages = append(packages, checked)
		}
		result = append(result, lock.Artifact{
			Name: record.Name, Platform: record.Platform, URL: record.URL, Path: record.Path,
			SHA256: record.SHA256, Size: record.Size, Dest: record.Dest, Unpack: &record.Unpack,
			UID: record.UID, GID: record.GID, Mode: record.Mode, SBOM: record.SBOM,
		})
	}
	return result, packages, nil
}

// packageArtifact is one checked local package: the control stanza its payload
// described and the platform it was acquired for.
type packageArtifact struct {
	platform string
	control  deb.Control
}

// checkArtifactPackages holds every package artifact to the rules of a fetched
// package: each dependency must already be satisfied by the packages this build
// selects, whole packages of the same platform included. Nothing is installed on its
// behalf, so a missing dependency is reported at lock time rather than as a runtime
// failure.
func checkArtifactPackages(packages []packageArtifact, whole []lock.Package) error {
	for i := range packages {
		if err := deb.ControlSatisfied(&packages[i].control, nativeArchitecture(packages[i].platform),
			samePlatform(packages, whole, i)); err != nil {
			return err
		}
	}
	return nil
}

// checkArtifactPackage reads one payload and checks it against what the
// specification declared for it.
func checkArtifactPackage(record *acquire.ArtifactRecord, request *Request) (packageArtifact, error) {
	data, err := request.Cache.Read(record.SHA256, record.Size)
	if err != nil {
		return packageArtifact{}, fmt.Errorf("artifact %q: %w", record.Name, err)
	}
	control, err := localControl(data, record.Name)
	if err != nil {
		return packageArtifact{}, err
	}
	if control.Name != record.SBOM.Name || control.Version != record.SBOM.Version {
		return packageArtifact{}, fmt.Errorf("artifact %q declares %s %s, but its payload is %s %s",
			record.Name, record.SBOM.Name, record.SBOM.Version, control.Name, control.Version)
	}
	native := nativeArchitecture(record.Platform)
	if control.Architecture != native && control.Architecture != deb.ArchitectureAll {
		return packageArtifact{}, fmt.Errorf("artifact %q is architecture %q, which does not fit %s",
			record.Name, control.Architecture, record.Platform)
	}
	return packageArtifact{platform: record.Platform, control: control}, nil
}

// nativeArchitecture returns the architecture of a platform. The platform was
// validated before it reached here, so an unknown one yields no architecture and
// every qualified dependency is refused.
func nativeArchitecture(platform string) string {
	architecture, _ := deb.Architecture(platform)
	return architecture
}

// samePlatform returns the packages selected for the platform of packages[at], so a
// local package is never satisfied by a package of another platform. A whole package's
// relations were resolved against the index, so only its name, version and
// architecture are known here.
func samePlatform(packages []packageArtifact, whole []lock.Package, at int) []deb.Control {
	selected := make([]deb.Control, 0, len(packages)+len(whole))
	for i := range packages {
		if packages[i].platform == packages[at].platform {
			selected = append(selected, packages[i].control)
		}
	}
	for i := range whole {
		if whole[i].Platform != packages[at].platform {
			continue
		}
		selected = append(selected, deb.Control{
			Name: whole[i].Name, Version: whole[i].Version, Architecture: whole[i].Architecture,
		})
	}
	return selected
}

// localControl decodes one local package's control stanza through the same reader
// the image build uses, so the lock-time check and the build cannot disagree.
func localControl(data []byte, name string) (deb.Control, error) {
	extracted, err := deb.Extract(data, vfs.Origin{Package: name, Path: name})
	if err != nil {
		return deb.Control{}, fmt.Errorf("artifact %q: %w", name, err)
	}
	stanza, ok := extracted.Control.Member("control")
	if !ok {
		return deb.Control{}, fmt.Errorf("artifact %q: payload has no control stanza", name)
	}
	control, err := deb.ParseControl(stanza)
	if err != nil {
		return deb.Control{}, fmt.Errorf("artifact %q: %w", name, err)
	}
	return control, nil
}
