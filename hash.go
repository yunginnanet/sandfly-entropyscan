package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"sync"
)

type HashType uint8

const (
	HashNull HashType = iota
	HashTypeMD5
	HashTypeSHA1
	HashTypeSHA256
	HashTypeSHA512
)

type HashResult struct {
	Type HashType
}

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

type MultiHasher struct {
	todo []HashType
}

func NewMultiHasher(types ...HashType) *MultiHasher {
	return &MultiHasher{todo: types}
}

func (m *MultiHasher) Hash(r io.Reader) (map[HashType]string, error) {
	if len(m.todo) == 0 {
		return nil, errors.New("no hash types specified")
	}

	var (
		res   = make(map[HashType]string, len(m.todo))
		errCh = make(chan error, len(m.todo))
		mu    sync.Mutex
	)

	wg := new(sync.WaitGroup)
	wg.Add(len(m.todo))

	for _, ht := range m.todo {
		go func(myHt HashType, myWg *sync.WaitGroup) {
			f, ok := HashEngines[myHt]
			if !ok {
				panic("hash engine not found: " + ht.String())
			}
			h := f()
			defer myWg.Done()
			buf := getBuf()
			defer putBuf(buf)
			n, err := io.CopyBuffer(h, r, buf)
			if err != nil || n == 0 {
				if err == nil {
					err = errors.New("no data written")
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

	return res, nil
}

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
