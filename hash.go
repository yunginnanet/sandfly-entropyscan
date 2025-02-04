package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"sync"

	"git.tcp.direct/kayos/common/pool"
)

// HashType is a type for hash types.
type HashType uint8

var bufs = pool.NewBufferFactory()

//goland:noinspection GoUnusedConst
const (
	HashNull HashType = iota
	HashTypeMD5
	HashTypeSHA1
	HashTypeSHA256
	HashTypeSHA512
)

// HashEngines is a map of hash types to hash functions.
var HashEngines = map[HashType]func() hash.Hash{
	HashTypeMD5:    md5.New,
	HashTypeSHA1:   sha1.New,
	HashTypeSHA256: sha256.New,
	HashTypeSHA512: sha512.New,
}

func (h HashType) String() string {
	switch h {
	case HashTypeMD5:
		return "md5"
	case HashTypeSHA1:
		return "sha1"
	case HashTypeSHA256:
		return "sha256"
	case HashTypeSHA512:
		return "sha512"
	default:
		return "unknown"
	}
}

var hashBufs = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 1024)
	},
}

func getBuf() []byte {
	b := hashBufs.Get().([]byte)
	b = b[:0]
	b = b[:cap(b)]
	return b
}

func putBuf(b []byte) {
	hashBufs.Put(b)
}

// MultiHasher is a struct for hashing multiple types of hashes.
type MultiHasher struct {
	todo []HashType
}

// NewMultiHasher creates a new MultiHasher.
func NewMultiHasher(types ...HashType) *MultiHasher {
	return &MultiHasher{todo: types}
}

// Hash hashes the data from the reader and returns a map of hash types to their corresponding hash values.
func (m *MultiHasher) Hash(r io.Reader) (map[HashType]string, error) {
	if len(m.todo) == 0 {
		return nil, errors.New("no hash types specified")
	}

	var (
		res   = make(map[HashType]string, len(m.todo))
		errCh = make(chan error, len(m.todo))
		errs  = make([]error, 0, len(m.todo))
		mu    sync.Mutex
	)

	bigBuf := bufs.Get()
	defer bufs.MustPut(bigBuf)

	fileN, readErr := bigBuf.ReadFrom(r)
	if readErr != nil && (!errors.Is(readErr, io.EOF) && fileN != 0) {
		return nil, readErr
	}
	if fileN == 0 {
		return nil, errors.New("no data read")
	}

	// we avoid reading directly from the reader incase it needs a rewind and avoid
	// repeating potential disk reads by reading once into bigBuf and creating
	// [bytes.Reader] instances from it's internal []byte slice within the goroutines.
	bufRaw := bigBuf.Bytes()

	wg := new(sync.WaitGroup)
	wg.Add(len(m.todo))

	for _, ht := range m.todo {
		go func(myHt HashType, myWg *sync.WaitGroup) {
			defer myWg.Done()
			f, ok := HashEngines[myHt]
			if !ok {
				panic("hash engine not found: " + myHt.String())
			}
			h := f()
			buf := getBuf()
			defer putBuf(buf)
			n, err := io.CopyBuffer(h, bytes.NewReader(bufRaw), buf)
			if err != nil || n == 0 {
				if err == nil {
					err = errors.New(myHt.String() + ": no data written")
				}
				errCh <- err
				return
			}
			mu.Lock()
			res[myHt] = hex.EncodeToString(h.Sum(nil))
			mu.Unlock()
		}(ht, wg)
	}

	wg.Wait()

	close(errCh)

	for err := range errCh {
		if err != nil {
			errs = append(errs, err)
		}
	}

	return res, errors.Join(errs...)
}

// HashFile hashes the file at the given path using [Hash].
func (m *MultiHasher) HashFile(path string) (map[HashType]string, error) {
	var err error
	var fSize int64
	var f io.ReadCloser
	var hashResults = make(map[HashType]string, len(m.todo))
	if f, fSize, err = preCheckFilepath(path); err != nil {
		return hashResults, err
	}

	defer func() {
		_ = f.Close()
	}()

	if fSize > int64(constMaxFileSize) {
		return hashResults, NewErrFileTooLarge(path, fSize)
	}

	return m.Hash(f)
}

func (cfg *config) runEnabledHashers(file *File) error {
	if file.Checksums == nil {
		file.Checksums = new(Checksums)
	}

	mh := NewMultiHasher(cfg.hashers...)

	results, err := mh.HashFile(file.Path)
	if err != nil {
		return err
	}
	for ht, res := range results {
		file.Checksums.Set(ht, res)
	}
	return nil
}
