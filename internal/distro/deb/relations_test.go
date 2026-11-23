package deb_test

import (
	"testing"

	"github.com/matt-mai/vapor/internal/distro/deb"
)

func TestParseDependencyList(t *testing.T) {
	clauses, err := deb.ParseDependencyList(
		"libc6 (>= 2.34), libfoo | libbar (= 1:2.0-1), python3:any", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(clauses) != 3 {
		t.Fatalf("len(clauses) = %d", len(clauses))
	}
	if len(clauses[0]) != 1 || clauses[0][0].Name != "libc6" ||
		clauses[0][0].Operator != deb.RelationGreaterOrEqual ||
		clauses[0][0].Version != (deb.Version{Upstream: "2.34"}) {
		t.Fatalf("first clause = %+v", clauses[0])
	}
	if len(clauses[1]) != 2 || clauses[1][0].Name != "libfoo" || clauses[1][0].Operator != "" ||
		clauses[1][1].Name != "libbar" || clauses[1][1].Operator != deb.RelationEqual ||
		clauses[1][1].Version != (deb.Version{Epoch: 1, Upstream: "2.0", Revision: "1"}) {
		t.Fatalf("second clause = %+v", clauses[1])
	}
	if len(clauses[2]) != 1 || clauses[2][0].Name != "python3" || clauses[2][0].Architecture != "any" {
		t.Fatalf("third clause = %+v", clauses[2])
	}
}

func TestParseDependencyListOperators(t *testing.T) {
	operators := map[string]deb.RelationOperator{
		"<<": deb.RelationLess,
		"<=": deb.RelationLessOrEqual,
		"=":  deb.RelationEqual,
		">=": deb.RelationGreaterOrEqual,
		">>": deb.RelationGreater,
	}
	for text, want := range operators {
		t.Run(text, func(t *testing.T) {
			clauses, err := deb.ParseDependencyList("demo ("+text+" 1:2.0-1)", "amd64")
			if err != nil {
				t.Fatal(err)
			}
			clause := clauses[0][0]
			if clause.Operator != want || clause.Version != (deb.Version{Epoch: 1, Upstream: "2.0", Revision: "1"}) {
				t.Fatalf("relation = %+v", clause)
			}
		})
	}
}

func TestParseDependencyListArchitectures(t *testing.T) {
	tests := []struct {
		name         string
		relation     string
		native       string
		wantArch     string
		wantRejected bool
	}{
		{"unqualified", "demo", "amd64", "", false},
		{"any", "demo:any", "amd64", "any", false},
		{"explicit native", "demo:amd64", "amd64", "amd64", false},
		{"explicit other native", "demo:arm64", "arm64", "arm64", false},
		{"foreign", "demo:i386", "amd64", "i386", false},
		{"all is not a qualifier", "demo:all", "amd64", "", true},
		{"build-only native qualifier", "demo:native", "amd64", "", true},
		{"empty qualifier", "demo:", "amd64", "", true},
		{"uppercase qualifier", "demo:AMD64", "amd64", "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clauses, err := deb.ParseDependencyList(test.relation, test.native)
			if test.wantRejected {
				if err == nil {
					t.Fatalf("ParseDependencyList(%q) succeeded", test.relation)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := clauses[0][0].Architecture; got != test.wantArch {
				t.Fatalf("architecture = %q, want %q", got, test.wantArch)
			}
		})
	}
}

func TestParseDependencyListKeepsForeignAlternative(t *testing.T) {
	// Real Ubuntu cross-build packages list a cross compiler first and a foreign
	// qualifier as a fallback, so the parser must not reject the whole field.
	clauses, err := deb.ParseDependencyList(
		"gcc-aarch64-linux-gnu (>= 4:14.2) | gcc:arm64, libc6", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(clauses) != 2 || len(clauses[0]) != 2 {
		t.Fatalf("clauses = %+v", clauses)
	}
	if clauses[0][0].Name != "gcc-aarch64-linux-gnu" || clauses[0][0].Architecture != "" {
		t.Fatalf("first alternative = %+v", clauses[0][0])
	}
	if clauses[0][1].Name != "gcc" || clauses[0][1].Architecture != "arm64" {
		t.Fatalf("second alternative = %+v", clauses[0][1])
	}
}

func TestParseDependencyListRequiresNativeArchitecture(t *testing.T) {
	if _, err := deb.ParseDependencyList("demo", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseDependencyListEmpty(t *testing.T) {
	clauses, err := deb.ParseDependencyList("", "amd64")
	if err != nil || clauses != nil {
		t.Fatalf("clauses = %v, err = %v", clauses, err)
	}
}

func TestParseDependencyListMalformed(t *testing.T) {
	for _, value := range []string{
		" ",
		"a,,b",
		"a |",
		"| a",
		"a (>=)",
		"a ()",
		"a (1.0)",
		"a (< 1.0)",
		"a (> 1.0)",
		"a (== 1.0)",
		"a (!= 1.0)",
		"a (=> 1.0)",
		"a (>= 1.0",
		"a (>= 1.0))",
		"a (>= 1.0) trailing",
		"a (>= 1.0) (<= 2.0)",
		"(>= 1.0)",
		"a (>= abc)",
		"a (>= 1_0)",
		"a (>= 1.0-)",
		"Demo",
		"a b",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := deb.ParseDependencyList(value, "amd64"); err == nil {
				t.Fatalf("ParseDependencyList(%q) succeeded", value)
			}
		})
	}
}

func TestParseProvidesList(t *testing.T) {
	clauses, err := deb.ParseProvidesList("demo (= 1.0), virtual", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(clauses) != 2 || len(clauses[0]) != 1 || len(clauses[1]) != 1 {
		t.Fatalf("clauses = %+v", clauses)
	}
	if clauses[0][0].Name != "demo" || clauses[0][0].Operator != deb.RelationEqual ||
		clauses[0][0].Version != (deb.Version{Upstream: "1.0"}) {
		t.Fatalf("versioned provider = %+v", clauses[0][0])
	}
	if clauses[1][0].Name != "virtual" || clauses[1][0].Operator != "" {
		t.Fatalf("provider = %+v", clauses[1][0])
	}
}

func TestParseProvidesListMalformed(t *testing.T) {
	for _, value := range []string{
		"demo (>= 1.0)",
		"demo (<< 1.0)",
		"demo | virtual",
		"demo (= 1.0), virtual (>= 2.0)",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := deb.ParseProvidesList(value, "amd64"); err == nil {
				t.Fatalf("ParseProvidesList(%q) succeeded", value)
			}
		})
	}
}

func TestParseConflictList(t *testing.T) {
	clauses, err := deb.ParseConflictList("old (<< 1.0), other (>= 2:1.0-1)", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(clauses) != 2 || len(clauses[0]) != 1 || len(clauses[1]) != 1 {
		t.Fatalf("clauses = %+v", clauses)
	}
	if clauses[0][0].Name != "old" || clauses[0][0].Operator != deb.RelationLess ||
		clauses[0][0].Version != (deb.Version{Upstream: "1.0"}) {
		t.Fatalf("first clause = %+v", clauses[0])
	}
	if clauses[1][0].Name != "other" || clauses[1][0].Operator != deb.RelationGreaterOrEqual ||
		clauses[1][0].Version != (deb.Version{Epoch: 2, Upstream: "1.0", Revision: "1"}) {
		t.Fatalf("second clause = %+v", clauses[1])
	}
}

func TestParseConflictListRejectsAlternatives(t *testing.T) {
	if _, err := deb.ParseConflictList("old | older", "amd64"); err == nil {
		t.Fatal("expected error")
	}
}
