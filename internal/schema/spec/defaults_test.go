package spec

import (
	"reflect"
	"testing"
)

func TestApplyDefaults_Platforms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		platforms, want []string
	}{
		{"omitted", nil, []string{"linux/amd64"}},
		{"explicit empty", []string{}, []string{}},
		{"explicit order", []string{"linux/arm64", "linux/amd64"}, []string{"linux/arm64", "linux/amd64"}},
		{"invalid left for validation", []string{"invalid"}, []string{"invalid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &Spec{Platforms: tt.platforms}
			applyDefaults(spec)
			if !reflect.DeepEqual(spec.Platforms, tt.want) {
				t.Fatalf("got %#v, want %#v", spec.Platforms, tt.want)
			}
			applyDefaults(spec)
			if !reflect.DeepEqual(spec.Platforms, tt.want) {
				t.Fatalf("defaults are not idempotent: %#v", spec.Platforms)
			}
		})
	}
}

func TestDecodeSpec_PreservesInputWithoutValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, input string
		want        []string
	}{
		{"omitted", minimalSpec, nil},
		{"explicit empty", minimalSpec + "platforms: []\n", []string{}},
		{"semantically invalid", minimalSpec + "platforms: [invalid]\n", []string{"invalid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := decodeSpec([]byte(tt.input))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(spec.Platforms, tt.want) {
				t.Fatalf("decoder changed input: got %#v, want %#v", spec.Platforms, tt.want)
			}
		})
	}
}
