package closure_test

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/closure"
	"github.com/matt-mai/vapor/internal/vfs"
)

const (
	machineAMD64 = 62
	machineARM64 = 183

	sectionNull    = 0
	sectionDynamic = 6
	sectionStrtab  = 3

	progLoad    = 1
	progDynamic = 2
	progInterp  = 3

	dynNeeded  = 1
	dynRpath   = 15
	dynRunpath = 29
	dynFlags1  = 0x6ffffffb
	dynNull    = 0
)

var origin = vfs.Origin{Package: "pkg", Slice: "pkg_slice", Path: "slices/pkg.yaml"}

// elfSpec describes the minimal object the tests need: an interpreter, the
// dependencies it names and the search paths it declares.
type elfSpec struct {
	interpreter string
	needed      []string
	rpath       string
	runpath     string
	machine     uint16
	pie         bool
}

func build(t *testing.T, spec elfSpec) []byte {
	t.Helper()
	if spec.machine == 0 {
		spec.machine = machineAMD64
	}

	strtab := []byte{0}
	str := func(s string) uint32 {
		if s == "" {
			return 0
		}
		off := uint32(len(strtab))
		strtab = append(strtab, s...)
		strtab = append(strtab, 0)
		return off
	}

	var dynamic []byte
	entry := func(tag uint64, value uint64) {
		dynamic = binary.LittleEndian.AppendUint64(dynamic, tag)
		dynamic = binary.LittleEndian.AppendUint64(dynamic, value)
	}
	for _, name := range spec.needed {
		entry(dynNeeded, uint64(str(name)))
	}
	if spec.rpath != "" {
		entry(dynRpath, uint64(str(spec.rpath)))
	}
	if spec.runpath != "" {
		entry(dynRunpath, uint64(str(spec.runpath)))
	}
	if spec.pie {
		entry(dynFlags1, 0x08000000)
	}
	entry(dynNull, 0)

	interp := append([]byte(spec.interpreter), 0)

	shstrtab := []byte{0}
	shstr := func(s string) uint32 {
		off := uint32(len(shstrtab))
		shstrtab = append(shstrtab, s...)
		shstrtab = append(shstrtab, 0)
		return off
	}
	nameDynamic := shstr(".dynamic")
	nameDynstr := shstr(".dynstr")
	nameShstrtab := shstr(".shstrtab")

	phnum := 2
	if spec.interpreter != "" {
		phnum++
	}
	const ehsize, phentsize, shentsize = 64, 56, 64
	phoff := uint64(ehsize)
	interpOff := phoff + uint64(phnum*phentsize)
	dynamicOff := interpOff + uint64(len(interp))
	dynstrOff := dynamicOff + uint64(len(dynamic))
	shstrtabOff := dynstrOff + uint64(len(strtab))
	shoff := shstrtabOff + uint64(len(shstrtab))

	out := make([]byte, shoff+4*shentsize)
	out[0], out[1], out[2], out[3] = 0x7f, 'E', 'L', 'F'
	out[4], out[5], out[6] = 2, 1, 1

	le := binary.LittleEndian
	le.PutUint16(out[16:], 3) // ET_DYN
	le.PutUint16(out[18:], spec.machine)
	le.PutUint32(out[20:], 1) // EV_CURRENT
	le.PutUint64(out[32:], phoff)
	le.PutUint64(out[40:], shoff)
	le.PutUint16(out[52:], ehsize)
	le.PutUint16(out[54:], phentsize)
	le.PutUint16(out[56:], uint16(phnum))
	le.PutUint16(out[58:], shentsize)
	le.PutUint16(out[60:], 4)
	le.PutUint16(out[62:], 3) // .shstrtab

	phdr := func(index int, typ uint32, off uint64, size uint64) {
		base := ehsize + index*phentsize
		le.PutUint32(out[base:], typ)
		le.PutUint32(out[base+4:], 4) // PF_R
		le.PutUint64(out[base+8:], off)
		le.PutUint64(out[base+32:], size)
		le.PutUint64(out[base+40:], size)
	}
	phdr(0, progLoad, 0, uint64(len(out)))
	next := 1
	if spec.interpreter != "" {
		phdr(next, progInterp, interpOff, uint64(len(interp)))
		next++
	}
	phdr(next, progDynamic, dynamicOff, uint64(len(dynamic)))

	copy(out[interpOff:], interp)
	copy(out[dynamicOff:], dynamic)
	copy(out[dynstrOff:], strtab)
	copy(out[shstrtabOff:], shstrtab)

	shdr := func(index int, name uint32, typ uint32, off uint64, size uint64, link uint32) {
		base := shoff + uint64(index*shentsize)
		le.PutUint32(out[base:], name)
		le.PutUint32(out[base+4:], typ)
		le.PutUint64(out[base+24:], off)
		le.PutUint64(out[base+32:], size)
		le.PutUint32(out[base+40:], link)
		le.PutUint64(out[base+48:], 1)
	}
	shdr(1, nameDynamic, sectionDynamic, dynamicOff, uint64(len(dynamic)), 2)
	shdr(2, nameDynstr, sectionStrtab, dynstrOff, uint64(len(strtab)), 0)
	shdr(3, nameShstrtab, sectionStrtab, shstrtabOff, uint64(len(shstrtab)), 0)
	return out
}

// staticELF is a 32-bit header-only object, used for the wrong-class case.
func staticELF(t *testing.T) []byte {
	t.Helper()
	out := make([]byte, 52)
	out[0], out[1], out[2], out[3] = 0x7f, 'E', 'L', 'F'
	out[4], out[5], out[6] = 1, 1, 1
	le := binary.LittleEndian
	le.PutUint16(out[16:], 2) // ET_EXEC
	le.PutUint16(out[18:], 3) // EM_386
	le.PutUint32(out[20:], 1)
	le.PutUint16(out[40:], 52)
	le.PutUint16(out[42:], 32)
	return out
}

func add(t *testing.T, tree *vfs.Tree, p string, data []byte) {
	t.Helper()
	if err := tree.File(p, data, vfs.Attrs{Mode: 0o755, Origin: origin}); err != nil {
		t.Fatalf("File %s: %v", p, err)
	}
}

// addLibrary writes an object with no execute bit, which is how a distribution ships a
// shared library. The loader still maps it, but only through a chain that reaches it.
func addLibrary(t *testing.T, tree *vfs.Tree, p string, data []byte) {
	t.Helper()
	if err := tree.File(p, data, vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
		t.Fatalf("File %s: %v", p, err)
	}
}

func addLink(t *testing.T, tree *vfs.Tree, p, target string) {
	t.Helper()
	if err := tree.Symlink(p, target, vfs.Attrs{Origin: origin}); err != nil {
		t.Fatalf("Symlink %s: %v", p, err)
	}
}

// completeTree holds an object whose interpreter and library both exist.
func completeTree(t *testing.T) *vfs.Tree {
	t.Helper()
	tree := vfs.New()
	add(t, tree, "/usr/lib/x86_64-linux-gnu/libc.so.6", build(t, elfSpec{}))
	add(t, tree, "/usr/lib/x86_64-linux-gnu/libm.so.6", build(t, elfSpec{}))
	add(t, tree, "/usr/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	addLink(t, tree, "/lib64", "usr/lib64")
	add(t, tree, "/usr/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libc.so.6"},
	}))
	return tree
}

func TestCheck_CompleteTree(t *testing.T) {
	if err := closure.Check(completeTree(t), "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestCheck_StaticObjectNeedsNothing(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/usr/bin/static", staticObject(t))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

// staticObject is a 64-bit amd64 object with no interpreter and no dynamic
// segment.
func staticObject(t *testing.T) []byte {
	t.Helper()
	out := make([]byte, 64)
	out[0], out[1], out[2], out[3] = 0x7f, 'E', 'L', 'F'
	out[4], out[5], out[6] = 2, 1, 1
	le := binary.LittleEndian
	le.PutUint16(out[16:], 2)
	le.PutUint16(out[18:], machineAMD64)
	le.PutUint32(out[20:], 1)
	le.PutUint16(out[52:], 64)
	le.PutUint16(out[54:], 56)
	return out
}

func TestCheck_ReportsMissingInterpreterAndLibrary(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/usr/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libc.so.6", "libz.so.1"},
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil {
		t.Fatal("expected failures")
	}
	for _, want := range []string{
		"/usr/bin/app: interpreter /lib64/ld-linux-x86-64.so.2 is missing",
		"/usr/bin/app: needs libc.so.6, which is not in the image",
		"/usr/bin/app: needs libz.so.1, which is not in the image",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want %q", err, want)
		}
	}
}

func TestCheck_LibraryThroughSymlinkChain(t *testing.T) {
	tree := completeTree(t)
	addLink(t, tree, "/usr/lib/x86_64-linux-gnu/libm.so", "libm.so.6")
	add(t, tree, "/usr/bin/user", build(t, elfSpec{needed: []string{"libm.so"}}))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestCheck_DanglingLibrarySymlinkIsMissing(t *testing.T) {
	tree := completeTree(t)
	addLink(t, tree, "/usr/lib/x86_64-linux-gnu/libgone.so", "libgone.so.1")
	add(t, tree, "/usr/bin/user", build(t, elfSpec{needed: []string{"libgone.so"}}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "needs libgone.so") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheck_RunpathAndRpath(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/opt/app/lib/libcustom.so.1", build(t, elfSpec{}))
	add(t, tree, "/opt/app/lib/libother.so.2", build(t, elfSpec{}))
	add(t, tree, "/opt/app/bin/app", build(t, elfSpec{
		needed:  []string{"libcustom.so.1"},
		runpath: "$ORIGIN/../lib",
	}))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}

	// DT_RPATH is ignored once DT_RUNPATH is present, as glibc does.
	add(t, tree, "/opt/app/bin/other", build(t, elfSpec{
		needed:  []string{"libother.so.2"},
		rpath:   "/opt/app/lib",
		runpath: "/nowhere",
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "needs libother.so.2") {
		t.Fatalf("error = %v", err)
	}
}

// glibc uses a loader's DT_RPATH for everything it pulls in, so a library may find
// its own dependency through the executable's RPATH.
func TestCheck_InheritsRpathFromTheLoader(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	add(t, tree, "/custom/liby.so.2", build(t, elfSpec{}))
	add(t, tree, "/custom/libx.so.1", build(t, elfSpec{needed: []string{"liby.so.2"}}))
	add(t, tree, "/opt/app/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libx.so.1"},
		rpath:       "/custom",
	}))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

// DT_RUNPATH applies only to the object that carries it, so it is not inherited.
func TestCheck_DoesNotInheritRunpath(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	add(t, tree, "/custom/liby.so.2", build(t, elfSpec{}))
	add(t, tree, "/custom/libx.so.1", build(t, elfSpec{needed: []string{"liby.so.2"}}))
	add(t, tree, "/opt/app/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libx.so.1"},
		runpath:     "/custom",
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "/custom/libx.so.1: needs liby.so.2") {
		t.Fatalf("error = %v", err)
	}
}

// glibc checks whether DT_RUNPATH is present, not whether it holds a usable
// directory, so a RUNPATH of ":" disables RPATH instead of falling back to it.
func TestCheck_EmptyRunpathDisablesRpath(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/opt/app/lib/libx.so.1", build(t, elfSpec{}))
	add(t, tree, "/opt/app/bin/app", build(t, elfSpec{
		needed:  []string{"libx.so.1"},
		rpath:   "/opt/app/lib",
		runpath: ":",
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "needs libx.so.1") {
		t.Fatalf("error = %v", err)
	}
}

// A search directory is resolved with filesystem semantics, not lexically: ".."
// after a symlinked component reaches the directory the link names.
func TestCheck_ResolvesSearchDirectoriesThroughSymlinks(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/real/deep/libx.so.1", build(t, elfSpec{}))
	addLink(t, tree, "/opt/link", "/real/deep")
	add(t, tree, "/opt/app/bin/app", build(t, elfSpec{
		needed:  []string{"libx.so.1"},
		runpath: "/opt/link/../deep",
	}))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}

	// The lexically cleaned form "/opt/deep" does not exist, so a checker that
	// cleaned first would report the library missing.
	add(t, tree, "/opt/app/bin/other", build(t, elfSpec{
		needed:  []string{"libx.so.1"},
		runpath: "/opt/link/../lib",
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "/opt/app/bin/other: needs libx.so.1") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheck_SkipsUnresolvedDollarDirectories(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/usr/lib/x86_64-linux-gnu/libc.so.6", build(t, elfSpec{}))
	add(t, tree, "/usr/bin/app", build(t, elfSpec{
		needed:  []string{"libc.so.6"},
		runpath: "/usr/lib/$LIB",
	}))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestCheck_NeededWithSlashIsAPath(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/opt/lib/libdirect.so.1", build(t, elfSpec{}))
	add(t, tree, "/usr/bin/app", build(t, elfSpec{needed: []string{"/opt/lib/libdirect.so.1"}}))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	add(t, tree, "/usr/bin/bad", build(t, elfSpec{needed: []string{"/opt/lib/libabsent.so.1"}}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "/opt/lib/libabsent.so.1") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheck_ReportsWrongClassMachineAndContent(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"wrong class", staticELF(t), "is ELF class ELFCLASS32"},
		{"wrong machine", build(t, elfSpec{machine: machineARM64}), "is machine EM_AARCH64"},
		{"unparsable", []byte("\x7fELF\x02\x01\x01\x00garbage"), "unparsable ELF content"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := vfs.New()
			add(t, tree, "/usr/bin/app", tc.data)
			err := closure.Check(tree, "linux/amd64")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCheck_ReportsDynamicSegmentWithoutSection(t *testing.T) {
	data := build(t, elfSpec{needed: []string{"libc.so.6"}})
	// Retag the .dynamic section as SHT_NULL, leaving PT_DYNAMIC in place.
	shoff := binary.LittleEndian.Uint64(data[40:])
	binary.LittleEndian.PutUint32(data[shoff+64+4:], sectionNull)
	tree := vfs.New()
	add(t, tree, "/usr/bin/app", data)
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "no dynamic section") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheck_DoesNotCopyHardlinkedELFBodies(t *testing.T) {
	const binarySize = 512 << 10
	tree := vfs.New()
	body := make([]byte, binarySize)
	copy(body, build(t, elfSpec{}))
	add(t, tree, "/bin/primary", body)
	for i := range 16 {
		if err := tree.Hardlink("/bin/link"+strconv.Itoa(i), "/bin/primary", origin); err != nil {
			t.Fatal(err)
		}
	}
	var checkErr error
	result := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			checkErr = closure.Check(tree, "linux/amd64")
		}
	})
	if checkErr != nil {
		t.Fatal(checkErr)
	}
	if got := result.AllocedBytesPerOp(); got >= binarySize {
		t.Fatalf("closure allocated %d bytes per check, want less than one binary body (%d bytes)", got, binarySize)
	}
}

func TestCheck_IgnoresNonELFAndArm64Tree(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/usr/share/doc/readme", []byte("not an object"))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}

	tree = vfs.New()
	add(t, tree, "/usr/lib/aarch64-linux-gnu/libc.so.6", build(t, elfSpec{machine: machineARM64}))
	add(t, tree, "/usr/bin/app", build(t, elfSpec{machine: machineARM64, needed: []string{"libc.so.6"}}))
	if err := closure.Check(tree, "linux/arm64"); err != nil {
		t.Fatalf("Check arm64: %v", err)
	}
}

func TestCheck_RejectsNilTreeAndUnsupportedPlatform(t *testing.T) {
	if err := closure.Check(nil, "linux/amd64"); err == nil {
		t.Fatal("expected an error for a nil tree")
	}
	if err := closure.Check(vfs.New(), "linux/riscv64"); err == nil {
		t.Fatal("expected an error for an unsupported platform")
	}
}

func TestCheck_ReportsFailuresInPathOrder(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/usr/bin/b", build(t, elfSpec{needed: []string{"libb.so"}}))
	add(t, tree, "/usr/bin/a", build(t, elfSpec{needed: []string{"liba.so"}}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil {
		t.Fatal("expected failures")
	}
	if strings.Index(err.Error(), "/usr/bin/a") > strings.Index(err.Error(), "/usr/bin/b") {
		t.Fatalf("failures are not in path order: %v", err)
	}
}

func TestCheck_RejectsUnloadableDependencies(t *testing.T) {
	const interp = "/lib64/ld-linux-x86-64.so.2"
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"linker script", []byte("GROUP ( libc.so.6 )")},
		{"wrong machine", build(t, elfSpec{machine: machineARM64})},
		{"no load segment", build(t, elfSpec{})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "no load segment" {
				binary.LittleEndian.PutUint32(test.body[64:], 0)
			}
			tree := vfs.New()
			add(t, tree, "/usr/bin/app", build(t, elfSpec{interpreter: interp, needed: []string{"libc.so.6"}}))
			add(t, tree, interp, test.body)
			add(t, tree, "/usr/lib/x86_64-linux-gnu/libc.so.6", test.body)
			err := closure.Check(tree, "linux/amd64")
			if err == nil || !strings.Contains(err.Error(), "/usr/bin/app: interpreter "+interp+":") ||
				!strings.Contains(err.Error(), "/usr/bin/app: needs libc.so.6 (") {
				t.Fatalf("Check = %v; want interpreter and library errors", err)
			}
		})
	}
}

func TestCheck_RejectsPIEAsLibrary(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/usr/bin/app", build(t, elfSpec{needed: []string{"libc.so.6"}}))
	add(t, tree, "/usr/lib/x86_64-linux-gnu/libc.so.6", build(t, elfSpec{pie: true}))
	if err := closure.Check(tree, "linux/amd64"); err == nil ||
		!strings.Contains(err.Error(), "ELF executable cannot be loaded as a library") {
		t.Fatalf("Check = %v; want PIE rejection", err)
	}
}

func TestCheck_DirectoriesAreNotLibrariesOrInterpreters(t *testing.T) {
	tree := vfs.New()
	if err := tree.Dir("/usr/lib/x86_64-linux-gnu/libc.so.6", vfs.Attrs{Mode: 0o755, Origin: origin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if err := tree.Dir("/lib64/ld-linux-x86-64.so.2", vfs.Attrs{Mode: 0o755, Origin: origin}); err != nil {
		t.Fatalf("Dir: %v", err)
	}
	add(t, tree, "/usr/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"},
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil {
		t.Fatal("expected failures")
	}
	for _, want := range []string{
		"interpreter /lib64/ld-linux-x86-64.so.2 is missing",
		"needs libc.so.6, which is not in the image",
		"needs /usr/lib/x86_64-linux-gnu/libc.so.6, which is not in the image",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want %q", err, want)
		}
	}
}

// The executable's RPATH reaches the end of a chain, not only the objects it loads
// directly: app -> liba -> libb -> libc all search through it.
func TestCheck_InheritsRpathThroughTheWholeChain(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	add(t, tree, "/custom/libc.so.3", build(t, elfSpec{}))
	add(t, tree, "/custom/libb.so.2", build(t, elfSpec{needed: []string{"libc.so.3"}}))
	add(t, tree, "/custom/liba.so.1", build(t, elfSpec{needed: []string{"libb.so.2"}}))
	add(t, tree, "/opt/app/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"liba.so.1"},
		rpath:       "/custom",
	}))
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

// An object that carries DT_RUNPATH has its DT_RPATH disabled, so it passes nothing
// on: children must not find their dependencies through the suppressed RPATH.
func TestCheck_SuppressedRpathIsNotInherited(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	add(t, tree, "/custom/liby.so.2", build(t, elfSpec{}))
	add(t, tree, "/custom/libx.so.1", build(t, elfSpec{needed: []string{"liby.so.2"}}))
	add(t, tree, "/opt/app/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libx.so.1"},
		rpath:       "/custom",
		runpath:     "/opt/app/lib",
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "/custom/libx.so.1: needs liby.so.2") {
		t.Fatalf("error = %v", err)
	}
}

// A child's own DT_RUNPATH suppresses the RPATH it inherits: it searches only its
// own directories.
func TestCheck_ChildRunpathSuppressesInheritedRpath(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	add(t, tree, "/custom/liby.so.2", build(t, elfSpec{}))
	add(t, tree, "/opt/app/lib/libx.so.1", build(t, elfSpec{
		needed:  []string{"liby.so.2"},
		runpath: "$ORIGIN",
	}))
	add(t, tree, "/opt/app/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libx.so.1"},
		rpath:       "/custom:/opt/app/lib",
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "/opt/app/lib/libx.so.1: needs liby.so.2") {
		t.Fatalf("error = %v", err)
	}
}

// Distribution packages ship ELF test fixtures that no loader will ever map.
// Go's source tree alone carries objects for a dozen machines; treating them as
// image executables rejects a correct image.
func TestCheck_IgnoresObjectsTheLoaderCannotReach(t *testing.T) {
	tree := completeTree(t)
	if err := tree.File("/usr/share/go/src/debug/elf/testdata/mips64.obj", staticELF(t),
		vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
		t.Fatalf("File: %v", err)
	}
	if err := closure.Check(tree, "linux/amd64"); err != nil {
		t.Fatalf("a non-executable fixture was inspected: %v", err)
	}
}

// The exemption is about reachability, not about ELF magic: a library the loader
// maps must still match the platform, even though nothing marks it executable.
func TestCheck_StillChecksALibraryTheLoaderMaps(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/usr/lib/x86_64-linux-gnu/libc.so.6", build(t, elfSpec{}))
	add(t, tree, "/usr/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	addLink(t, tree, "/lib64", "usr/lib64")
	// A 32-bit library that libm is loaded from: the chain reaches it, so it must
	// match the platform even though no execute bit marks it.
	if err := tree.File("/usr/lib/x86_64-linux-gnu/libm.so.6", staticELF(t),
		vfs.Attrs{Mode: 0o644, Origin: origin}); err != nil {
		t.Fatalf("File: %v", err)
	}
	add(t, tree, "/usr/bin/app", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libc.so.6", "libm.so.6"},
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "libm.so.6") {
		t.Fatalf("error = %v", err)
	}
}

// Two executables can load the same library, and each brings its own RPATH. The
// library's dependency is reachable through one of them only, so a single chain
// recorded for the library across the whole image would accept the other loader's
// process, where the dependency cannot be found.
func TestCheck_InheritsPerLoaderNotPerImage(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	add(t, tree, "/shared/libshared.so.1", build(t, elfSpec{needed: []string{"libprivate.so.2"}}))
	add(t, tree, "/one/libprivate.so.2", build(t, elfSpec{}))
	add(t, tree, "/optapp/bin/first", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libshared.so.1"},
		rpath:       "/shared:/one",
	}))
	add(t, tree, "/optapp/bin/second", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libshared.so.1"},
		rpath:       "/shared",
	}))
	err := closure.Check(tree, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "not found by the search path reaching it from /optapp/bin/second") {
		t.Fatalf("error = %v", err)
	}
}

// Two executables can share a library and carry different inherited RPATHs. Each
// process searches its own chain, so the library that chain selects is the one whose
// dependencies that process must satisfy. Here the second executable's chain shadows
// libz with a copy that needs a library of its own, and only that copy is missing it.
// The libraries are not executable, as in a real image, so they are only judged where
// a chain reaches them.
func TestCheck_EachExecutableSearchesItsOwnChain(t *testing.T) {
	tree := vfs.New()
	add(t, tree, "/lib64/ld-linux-x86-64.so.2", build(t, elfSpec{}))
	// The ordinary copy the first executable finds: its dependencies are complete.
	addLibrary(t, tree, "/opt/app/lib/libz.so.3", build(t, elfSpec{}))
	// The copy the second executable's chain selects, which needs a library it cannot
	// find. Only the second executable loads it.
	addLibrary(t, tree, "/custom/libz.so.3", build(t, elfSpec{needed: []string{"liby.so.2"}}))
	addLibrary(t, tree, "/opt/app/lib/libx.so.1", build(t, elfSpec{needed: []string{"libz.so.3"}}))
	add(t, tree, "/opt/app/bin/a", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libx.so.1"},
		rpath:       "/opt/app/lib",
	}))
	add(t, tree, "/opt/app/bin/b", build(t, elfSpec{
		interpreter: "/lib64/ld-linux-x86-64.so.2",
		needed:      []string{"libx.so.1"},
		rpath:       "/custom:/opt/app/lib",
	}))
	err := closure.Check(tree, "linux/amd64")
	want := "/custom/libz.so.3: needs liby.so.2"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}
