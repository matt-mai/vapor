package mutation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"syscall"
)

// These are the first two ExtraFiles in the worker, not VFS or host descriptors.
const (
	readRequestFD = 3
	readBodyFD    = 4
)

type fileMetadata struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest []byte `json:"sha256,omitempty"`
}

type openImageFile func(string) (*bytes.Reader, error)

type readPipe struct {
	requests, sendID    *os.File
	receiveBody, bodies *os.File
}

func newReadPipe() (*readPipe, error) {
	requests, sendID, err := os.Pipe()
	if err != nil {
		return nil, errors.New("mutation could not create the file request pipe")
	}
	receiveBody, bodies, err := os.Pipe()
	if err != nil {
		_ = requests.Close()
		_ = sendID.Close()
		return nil, errors.New("mutation could not create the file body pipe")
	}
	return &readPipe{requests: requests, sendID: sendID, receiveBody: receiveBody, bodies: bodies}, nil
}

func (p *readPipe) closeChildEnds() {
	_ = p.sendID.Close()
	_ = p.receiveBody.Close()
}

func (p *readPipe) closeParentEnds() {
	_ = p.requests.Close()
	_ = p.bodies.Close()
}

func (p *readPipe) run(
	ctx context.Context, command *exec.Cmd, files []fileMetadata, open openImageFile, budget int64,
) (error, error) {
	defer p.closeParentEnds()
	stop := context.AfterFunc(ctx, p.closeParentEnds)
	defer stop()
	command.ExtraFiles = []*os.File{p.sendID, p.receiveBody}
	err := command.Start()
	p.closeChildEnds()
	if err != nil {
		return err, nil
	}
	done := make(chan error, 1)
	go func() {
		err := serveReads(p.requests, p.bodies, files, open, budget)
		if err != nil && !errors.Is(err, errBodyPipeClosed) {
			// A worker that has lost its broker must not produce an accepted result.
			_ = command.Process.Kill()
		}
		done <- err
	}()
	runErr := command.Wait()
	// The child owns the other ends; exit or cancellation unblocks both pipes.
	return runErr, <-done
}

func serveReads(ids io.Reader, bodies io.Writer, files []fileMetadata, open openImageFile, remaining int64) error {
	var frame [4]byte
	for {
		_, err := io.ReadFull(ids, frame[:])
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return &ScriptError{Kind: FailureWorkerDeath, Message: "worker file request is incomplete"}
		}
		id := binary.BigEndian.Uint32(frame[:])
		if uint64(id) >= uint64(len(files)) {
			return &ScriptError{Kind: FailureWorkerDeath, Message: "worker requested an unknown image file"}
		}
		file := files[id]
		if file.Size <= 0 || file.Size > remaining {
			return &ScriptError{Kind: FailureRead, Message: "worker file request exceeds the read bound"}
		}
		remaining -= file.Size
		if err := sendBody(bodies, open, file); err != nil {
			return err
		}
	}
}

var errBodyPipeClosed = &ScriptError{Kind: FailureWorkerDeath, Message: "worker closed the file body pipe"}

func sendBody(dst io.Writer, open openImageFile, file fileMetadata) error {
	body, err := openBody(open, file)
	if err != nil {
		return err
	}
	_, err = body.WriteTo(dst)
	if errors.Is(err, syscall.EPIPE) {
		return errBodyPipeClosed
	}
	if err != nil {
		return &ScriptError{Kind: FailureWorkerDeath, Message: "worker file transfer failed"}
	}
	return nil
}

func openBody(open openImageFile, file fileMetadata) (*bytes.Reader, error) {
	body, err := open(file.Name)
	if err != nil || body == nil || body.Size() != file.Size {
		return nil, &ScriptError{Kind: FailureWorkerDeath, Message: "staged image file does not match worker metadata"}
	}
	return body, nil
}

func receiveBody(ids io.Writer, bodies io.Reader, id uint32, size int64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if size < 0 || size > math.MaxInt {
		return nil, &ScriptError{Kind: FailureRead, Message: "image file exceeds the read bound"}
	}
	data := make([]byte, int(size))
	var frame [4]byte
	binary.BigEndian.PutUint32(frame[:], id)
	if n, err := ids.Write(frame[:]); err != nil || n != len(frame) {
		return nil, &ScriptError{Kind: FailureWorkerDeath, Message: "worker file request failed"}
	}
	if _, err := io.ReadFull(bodies, data); err != nil {
		return nil, &ScriptError{Kind: FailureWorkerDeath, Message: "worker file transfer is incomplete"}
	}
	return data, nil
}

// Only files that can be rewritten at their current size need a digest.
func indexDigests(ctx context.Context, request *ScriptRequest, maxWrite int64, open openImageFile) error {
	if len(request.Mutable) == 0 {
		return nil
	}
	mutable := writablePaths(request)
	for i := range request.FileIndex {
		file := &request.FileIndex[i]
		if !mutable[file.Name] || file.Size > maxWrite {
			continue
		}
		if err := canceled(ctx); err != nil {
			return err
		}
		original, err := openBody(open, *file)
		if err != nil {
			return err
		}
		hash := sha256.New()
		if _, err := original.WriteTo(hash); err != nil {
			return err
		}
		file.Digest = hash.Sum(nil)
	}
	return nil
}
