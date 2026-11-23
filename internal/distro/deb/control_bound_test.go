package deb

import (
	"archive/tar"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/matt-mai/vapor/internal/vfs"
)

// paxRecord formats one PAX record the way the tar format requires: a decimal
// length that includes its own digits, then " key=value\n".
func paxRecord(key, value string) string {
	body := " " + key + "=" + value + "\n"
	size := len(body) + 1
	for len(strconv.Itoa(size))+len(body) != size {
		size = len(strconv.Itoa(size)) + len(body)
	}
	return strconv.Itoa(size) + body
}

// rawHeader writes one 512-byte ustar header. archive/tar cannot produce a
// sparse member, so fixtures for one are assembled by hand.
func rawHeader(buffer *bytes.Buffer, name string, typeflag byte, size int64) {
	var header [512]byte
	copy(header[0:100], name)
	copy(header[100:108], "0000644\x00")
	copy(header[108:116], "0000000\x00")
	copy(header[116:124], "0000000\x00")
	copy(header[124:136], fmt.Sprintf("%011o\x00", size))
	copy(header[136:148], "00000000000\x00")
	for i := 148; i < 156; i++ {
		header[i] = ' '
	}
	header[156] = typeflag
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	sum := 0
	for _, b := range &header {
		sum += int(b)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
	buffer.Write(header[:])
}

func padToBlock(buffer *bytes.Buffer) {
	if remainder := buffer.Len() % 512; remainder != 0 {
		buffer.Write(make([]byte, 512-remainder))
	}
}

// sparseTar assembles a control tarball whose single member declares logical
// bytes it does not store. A tar reader synthesizes the holes, so reading it
// whole yields header.Size bytes from a payload that is a few hundred.
func sparseTar(t *testing.T, name string, logical int64, dense []byte) []byte {
	t.Helper()
	records := paxRecord("GNU.sparse.major", "0") +
		paxRecord("GNU.sparse.minor", "0") +
		paxRecord("GNU.sparse.numblocks", "1") +
		paxRecord("GNU.sparse.offset", "0") +
		paxRecord("GNU.sparse.numbytes", strconv.Itoa(len(dense))) +
		paxRecord("GNU.sparse.size", strconv.FormatInt(logical, 10))
	var buffer bytes.Buffer
	rawHeader(&buffer, "PaxHeaders.0/"+name, tar.TypeXHeader, int64(len(records)))
	buffer.WriteString(records)
	padToBlock(&buffer)
	rawHeader(&buffer, name, tar.TypeReg, int64(len(dense)))
	buffer.Write(dense)
	padToBlock(&buffer)
	buffer.Write(make([]byte, 1024))
	return buffer.Bytes()
}

// controlTar assembles a plain control tarball with the given members.
func controlTar(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for name, content := range members {
		if err := writer.WriteHeader(&tar.Header{
			Name: "./" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("write header %q: %v", name, err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buffer.Bytes()
}

// TestSparseControlMemberYieldsMoreThanItStores pins the premise of the budget:
// the tar reader reports the declared size and hands back that many bytes even
// though the member stores almost nothing.
func TestSparseControlMemberYieldsMoreThanItStores(t *testing.T) {
	t.Parallel()
	data := sparseTar(t, "control", 8<<20, []byte("x"))
	reader := tar.NewReader(bytes.NewReader(data))
	header, err := reader.Next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if header.Size != 8<<20 {
		t.Fatalf("declared size = %d, want %d", header.Size, 8<<20)
	}
	if len(data) > 4096 {
		t.Fatalf("fixture stores %d bytes, so it does not demonstrate amplification", len(data))
	}
}

// TestReadControlEvidenceRejectsASparseMemberOverBudget is the reported defect: a
// member whose declared size passes the stream bound would still be read whole,
// allocating far more than the control limit allows.
func TestReadControlEvidenceRejectsASparseMemberOverBudget(t *testing.T) {
	t.Parallel()
	data := sparseTar(t, "postinst", MaxControlArchiveSize+(1<<20), []byte("x"))
	if _, err := readControlEvidence(data); err == nil ||
		!strings.Contains(err.Error(), "control evidence exceeds") {
		t.Fatalf("error = %v, want a control evidence budget error", err)
	}
}

// TestReadControlEvidenceChargesEveryMember covers the bound the per-stream limit
// cannot make: the members fit the stored-bytes limit individually, so only the
// running total catches them.
func TestReadControlEvidenceChargesEveryMember(t *testing.T) {
	t.Parallel()
	half := (MaxControlArchiveSize / 2) + 1
	data := sparseTar(t, "control", half, []byte("x"))
	second := sparseTar(t, "md5sums", half, []byte("y"))
	// Strip the second archive's end-of-archive blocks and concatenate, so both
	// members share one stream that is still far below the stored-byte bound.
	joined := append(append([]byte{}, data[:len(data)-1024]...), second[:len(second)-1024]...)
	joined = append(joined, make([]byte, 1024)...)
	if int64(len(joined)) > MaxControlArchiveSize {
		t.Fatalf("fixture stores %d bytes, which exceeds the stream bound itself", len(joined))
	}
	if _, err := readControlEvidence(joined); err == nil ||
		!strings.Contains(err.Error(), "control evidence exceeds") {
		t.Fatalf("error = %v, want the total budget to be enforced", err)
	}
}

// TestReadControlEvidenceAcceptsALargeControl guards the budget against rejecting
// ordinary evidence: real control tarballs are about a hundred KiB.
func TestReadControlEvidenceAcceptsALargeControl(t *testing.T) {
	t.Parallel()
	control := controlTar(t, map[string][]byte{
		"control":  []byte("Package: demo\nVersion: 1.0\n"),
		"md5sums":  bytes.Repeat([]byte("d41d8cd98f00b204e9800998ecf8427e  usr/bin/tool\n"), 1000),
		"postinst": []byte("#!/bin/sh\nexit 0\n"),
	})
	evidence, err := readControlEvidence(control)
	if err != nil {
		t.Fatalf("readControlEvidence: %v", err)
	}
	if len(evidence.Members) != 3 {
		t.Fatalf("retained %d members, want 3", len(evidence.Members))
	}
	for _, member := range evidence.Members {
		data, ok := evidence.Member(member.Name)
		if !ok || len(data) != len(member.Data) {
			t.Fatalf("member %q is not retrievable", member.Name)
		}
	}
}

// TestExtractRejectsASparseControlMember drives the same case through the public
// entry point, so the budget is proven to apply to a decoded package and not only
// to the helper.
func TestExtractRejectsASparseControlMember(t *testing.T) {
	t.Parallel()
	control := sparseTar(t, "postinst", MaxControlArchiveSize+(1<<20), []byte("x"))
	data := testArArchive(t,
		arMember{name: "debian-binary", body: []byte("2.0\n")},
		arMember{name: "control.tar.gz", body: gzipBytes(t, control)},
		arMember{name: "data.tar.gz", body: gzipBytes(t, make([]byte, 1024))})
	if _, err := Extract(data, vfs.Origin{Package: "demo"}); err == nil ||
		!strings.Contains(err.Error(), "control evidence exceeds") {
		t.Fatalf("error = %v, want a control evidence budget error", err)
	}
}

// TestReadControlEvidenceRejectsAShortMember ensures the budgeted read still
// fails when a member yields less than it declares.
func TestReadControlEvidenceRejectsAShortMember(t *testing.T) {
	t.Parallel()
	control := controlTar(t, map[string][]byte{"control": []byte("short")})
	// Claim more than the member holds and drop the other archive blocks.
	broken := append([]byte{}, control...)
	copy(broken[124:136], "00000000020\x00")
	if _, err := readControlEvidence(broken); err == nil {
		t.Fatal("a member shorter than its declared size was accepted")
	}
}
