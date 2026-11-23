package spec

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestSpecDigest_MeaningfulEdits(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*Spec){
		"annotation":                   func(s *Spec) { s.Annotations["a"] = "different" },
		"environment":                  func(s *Spec) { s.Container.Env["A"] = "different" },
		"command":                      func(s *Spec) { s.Container.Cmd[1] = "9000" },
		"artifact digest":              func(s *Spec) { s.Contents.Artifacts[0].Sources[0].SHA256 = strings.Repeat("b", 64) },
		"catalogue rename":             func(s *Spec) { s.Contents.Catalogues[1].Path = new("catalogues/renamed") },
		"key rename":                   func(s *Spec) { s.Contents.Repositories[0].Trust.Keys[0].Path = "keys/renamed.asc" },
		"suite matching":               func(s *Spec) { s.Contents.Repositories[0].SuiteMatch = new("codename") },
		"CA rename":                    func(s *Spec) { s.Filesystem.CA.Sources[0] = "certs/renamed.pem" },
		"VEX rename":                   func(s *Spec) { s.VEX.Inputs[0] = "vex/renamed.json" },
		"workdir":                      func(s *Spec) { s.Container.Workdir = "/other" },
		"artifact destination":         func(s *Spec) { s.Contents.Artifacts[0].Dest = "/other/server" },
		"image entry":                  func(s *Spec) { s.Filesystem.Paths[2].Path = "/other-marker" },
		"symlink target":               func(s *Spec) { s.Filesystem.Paths[1].Target = new("/other/server") },
		"account home":                 func(s *Spec) { s.Filesystem.Accounts.Users[0].Home = new("/home/app") },
		"account shell":                func(s *Spec) { s.Filesystem.Accounts.Users[0].Shell = new("/bin/false") },
		"absence evidence":             func(s *Spec) { s.VEX.Assertions[0].AbsentPaths[0] = "/other/path" },
		"SBOM false vs default":        func(s *Spec) { s.SBOM.Enabled = nil },
		"hardening false vs default":   func(s *Spec) { s.Hardening.StripDocs = nil },
		"VEX false vs default":         func(s *Spec) { s.VEX.CheckAbsentPaths = new(false) },
		"large integer":                func(s *Spec) { s.Contents.SlicesEngine.MaxSteps = new(9007199254740992) },
		"explicit timezone vs omitted": func(s *Spec) { s.Filesystem.Timezone = nil },
	} {
		t.Run(name, func(t *testing.T) {
			spec := digestVectorSpec(t)
			before := requireDigest(t, spec)
			change(spec)
			if requireDigest(t, spec) == before {
				t.Fatal("meaningful declaration edit did not change digest")
			}
		})
	}
}

func TestSpecDigest_ProgrammaticValidation(t *testing.T) {
	t.Parallel()
	var absent *Spec
	if digest, err := absent.SpecDigest(); digest != "" || err == nil {
		t.Fatal("nil receiver accepted")
	}
	for name, change := range map[string]func(*Spec){
		"version":                  func(s *Spec) { s.Version = 0 },
		"image platforms":          func(s *Spec) { s.Platforms = []string{} },
		"repository scope":         func(s *Spec) { s.Contents.Repositories[0].Platforms = []string{} },
		"artifact scope":           func(s *Spec) { s.Contents.Artifacts[0].Platforms = []string{} },
		"missing evidence":         func(s *Spec) { s.VEX.Assertions[0].AbsentPaths = nil },
		"forbidden empty evidence": func(s *Spec) { s.VEX.Assertions[1].AbsentPaths = []string{} },
		"absolute catalogue":       func(s *Spec) { s.Contents.Catalogues[1].Path = new("/host/catalogue") },
		"absolute key":             func(s *Spec) { s.Contents.Repositories[0].Trust.Keys[0].Path = "/host/key" },
		"absolute CA":              func(s *Spec) { s.Filesystem.CA.Sources[0] = "/host/ca" },
		"absolute VEX":             func(s *Spec) { s.VEX.Inputs[0] = "/host/vex" },
	} {
		t.Run(name, func(t *testing.T) {
			spec := digestVectorSpec(t)
			change(spec)
			if digest, err := spec.SpecDigest(); digest != "" || err == nil {
				t.Fatal("invalid programmatic spec accepted")
			}
		})
	}
	for i, bad := range []string{"private_marker\x00", "${private_marker}", "private_marker\xff"} {
		for name, change := range map[string]func(*Spec){
			"map value": func(s *Spec) { s.Container.Env["A"] = bad },
			"map key":   func(s *Spec) { s.Annotations[bad] = "text" },
		} {
			t.Run(strconv.Itoa(i)+name, func(t *testing.T) {
				spec := digestVectorSpec(t)
				change(spec)
				digest, err := spec.SpecDigest()
				if digest != "" || err == nil || strings.Contains(err.Error(), "private_marker") {
					t.Fatalf("want redacted rejection: %v", err)
				}
			})
		}
	}
}

func TestCanonicalValue_UnsupportedKindsFail(t *testing.T) {
	t.Parallel()
	for _, input := range []any{1.5, []float64{1.5}, map[string]float64{"x": 1.5}, struct{ X float64 }{X: 1.5}} {
		value := reflect.ValueOf(input)
		if _, err := canonicalValue(value); err == nil {
			t.Fatal("unsupported canonical schema kind accepted")
		}
		if err := checkDigestText(value); err == nil {
			t.Fatal("unsupported input schema kind accepted")
		}
	}
}
