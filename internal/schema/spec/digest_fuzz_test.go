package spec

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzSpecDigest_Immutable(f *testing.F) {
	f.Add([]byte(minimalSpec))
	f.Add([]byte(minimalSpec + "annotations: {a: value}\n"))
	f.Add([]byte(contentsFixture))
	f.Fuzz(func(t *testing.T, input []byte) {
		spec, err := decodeSpec(input)
		if err != nil {
			return
		}
		before, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		digest, digestErr := spec.SpecDigest()
		after, err := json.Marshal(spec)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("digest modified caller: %v", err)
		}
		if digestErr != nil {
			if digest != "" {
				t.Fatal("invalid spec returned a digest")
			}
			return
		}
		if repeated, err := spec.SpecDigest(); err != nil || repeated != digest {
			t.Fatalf("unstable digest: %v", err)
		}
	})
}
