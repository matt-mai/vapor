package mutation

import (
	"bytes"
	"os"
	"strconv"
	"testing"
)

func TestServeReadsChecksIDAndBudgetBeforeOpening(t *testing.T) {
	for _, tt := range []struct {
		name  string
		ids   string
		limit int64
		want  string
		kind  FailureKind
	}{
		{"no requests", "", 3, "", ""},
		{"read one", "\x00\x00\x00\x00", 3, "abc", ""},
		{"short frame", "\x00\x00\x00", 3, "", FailureWorkerDeath},
		{"unknown ID", "\x00\x00\x00\x01", 3, "", FailureWorkerDeath},
		{"too large", "\x00\x00\x00\x00", 2, "", FailureRead},
		{"repeated read", "\x00\x00\x00\x00\x00\x00\x00\x00", 5, "abc", FailureRead},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var body bytes.Buffer
			opens := 0
			err := serveReads(bytes.NewBufferString(tt.ids), &body, []fileMetadata{{Name: "/data", Size: 3}},
				func(path string) (*bytes.Reader, error) {
					opens++
					if path != "/data" {
						t.Errorf("opened %q, want /data", path)
					}
					return bytes.NewReader([]byte("abc")), nil
				}, tt.limit)
			if tt.kind != "" {
				requireReadError(t, err, tt.kind)
			} else if err != nil {
				t.Fatal(err)
			}
			if body.String() != tt.want || opens != len(tt.want)/3 {
				t.Fatalf("body = %q, opened %d files", body.String(), opens)
			}
		})
	}
}

func TestReadPipeRejectsIncorrectSize(t *testing.T) {
	var body bytes.Buffer
	err := sendBody(&body, func(string) (*bytes.Reader, error) {
		return bytes.NewReader([]byte("too long")), nil
	}, fileMetadata{Name: "/data", Size: 3})
	requireReadError(t, err, FailureWorkerDeath)
	if body.Len() != 0 {
		t.Fatal("incorrect file body was written")
	}
	_, err = receiveBody(&body, bytes.NewBufferString("ab"), 1, 3)
	requireReadError(t, err, FailureWorkerDeath)
	if got := body.String(); got != "\x00\x00\x00\x01" {
		t.Fatalf("file request = %x", got)
	}
}

func TestSendBodyReportsClosedPipe(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = read.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = write.Close() })
	err = sendBody(write, func(string) (*bytes.Reader, error) {
		return bytes.NewReader([]byte("abc")), nil
	}, fileMetadata{Name: "/data", Size: 3})
	if err != errBodyPipeClosed {
		t.Fatalf("sendBody = %v, want closed pipe", err)
	}
}

func requireReadError(t *testing.T, err error, want FailureKind) {
	t.Helper()
	scriptErr, ok := err.(*ScriptError)
	if !ok || scriptErr.Kind != want {
		t.Fatalf("read error = %v, want %s", err, want)
	}
}

func TestRunScriptTransfersOnlyRequestedBodies(t *testing.T) {
	if err := SandboxSupported(); err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	files := make([]fileMetadata, 0, 5002)
	files = append(files, fileMetadata{Name: "/small", Size: 3}, fileMetadata{Name: "/empty", Size: 0})
	for i := range 5000 {
		files = append(files, fileMetadata{Name: "/large/item-" + strconv.Itoa(i), Size: 32 << 10})
	}
	limits := DefaultSandboxLimits()
	limits.MaxMessageBytes = 1 << 20
	limits.MaxReadBytes = 3
	for _, tt := range []struct {
		name   string
		script string
		opens  int
	}{
		{"no-op", `pass`, 0},
		{"small read", `if content.read("/empty") != "" or content.read("/alias") != "abc": fail("read changed")`, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := &ScriptRequest{
				Script: []byte(tt.script), MaxSteps: 100, FileIndex: files,
				Links: map[string]string{"/alias": "/small"},
			}
			opens := 0
			result, err := runScript(t.Context(), request, &limits, func(path string) (*bytes.Reader, error) {
				opens++
				if path != "/small" {
					t.Errorf("opened %q, want /small", path)
				}
				return bytes.NewReader([]byte("abc")), nil
			})
			if err != nil || opens != tt.opens || len(result.Writes) != 0 {
				t.Fatalf("opened %d files, result = %+v, error = %v", opens, result, err)
			}
		})
	}
}

func TestRunScriptDropsRevertedWrites(t *testing.T) {
	if err := SandboxSupported(); err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	result, err := RunScript(t.Context(), &ScriptRequest{
		Script: []byte(`content.write("/data", "new")
content.write("/data", "old")
content.write("/empty", "")
content.write("/change", "new")`), MaxSteps: 100,
		Files:   map[string][]byte{"/data": []byte("old"), "/empty": {}, "/change": []byte("old")},
		Mutable: []string{"/data", "/empty", "/change"},
	}, DefaultSandboxLimits())
	if err != nil || len(result.Writes) != 1 || string(result.Writes["/change"]) != "new" {
		t.Fatalf("write delta = %+v, error = %v; want only changed file", result, err)
	}
}
