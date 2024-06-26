package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
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

var HashFuncs = map[HashType]func() hash.Hash{
	HashTypeMD5:    md5.New,
	HashTypeSHA1:   sha1.New,
	HashTypeSHA256: sha256.New,
	HashTypeSHA512: sha512.New,
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
	var res = make(map[HashType]string, len(m.todo))
	hashers := make([]hash.Hash, 0, len(m.todo))

	for _, v := range m.todo {
		f, ok := HashFuncs[v]
		if !ok {
			return res, fmt.Errorf("hash type (%d) not supported", v)
		}
		hashers = append(hashers, f())
	}
	var errCh = make(chan error, len(m.todo))
	wg := new(sync.WaitGroup)
	wg.Add(len(m.todo))
	for _, h := range hashers {
		go func(h hash.Hash, w *sync.WaitGroup) {
			defer w.Done()
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
			res[HashTypeMD5] = hex.EncodeToString(h.Sum(nil))
		}(h, wg)
	}

	wg.Wait()

	return res, nil
}

// HashMD5 calculates the MD5 checksum of a file.
func HashMD5(path string) (hash string, err error) {
	var fSize int64
	var f io.ReadCloser
	if f, fSize, err = preCheckFilepath(path); err != nil {
		return hash, err
	}

	defer func() {
		_ = f.Close()
	}()

	if fSize > int64(constMaxFileSize) {
		return hash, NewErrFileTooLarge(path, fSize)
	}

	hashMD5 := md5.New()
	_, err = io.Copy(hashMD5, f)
	if err != nil {
		return hash, fmt.Errorf("couldn't read path (%s) to get MD5 hash: %w", path, err)
	}

	hash = hex.EncodeToString(hashMD5.Sum(nil))

	return hash, nil
}

// HashSHA1 calculates the SHA1 checksum of a file.
func HashSHA1(path string) (hash string, err error) {
	var fSize int64
	var f io.ReadCloser

	if f, fSize, err = preCheckFilepath(path); err != nil {
		return hash, err
	}

	defer func() {
		_ = f.Close()
	}()

	if fSize > int64(constMaxFileSize) {
		return hash, NewErrFileTooLarge(path, fSize)
	}

	hashSHA1 := sha1.New()
	_, err = io.Copy(hashSHA1, f)
	if err != nil {
		return hash, fmt.Errorf("couldn't read path (%s) to get SHA1 hash: %w", path, err)
	}

	hash = hex.EncodeToString(hashSHA1.Sum(nil))

	return hash, nil
}

// HashSHA256 calculates the SHA256 checksum of a file.
func HashSHA256(path string) (hash string, err error) {
	var fSize int64
	var f io.ReadCloser

	if f, fSize, err = preCheckFilepath(path); err != nil {
		return hash, err
	}

	defer func() {
		_ = f.Close()
	}()

	if fSize > int64(constMaxFileSize) {
		return hash, NewErrFileTooLarge(path, fSize)
	}

	hashSHA256 := sha256.New()
	_, err = io.Copy(hashSHA256, f)
	if err != nil {
		return hash, fmt.Errorf("couldn't read '%s' to get SHA256 hash: %w", path, err)
	}

	hash = hex.EncodeToString(hashSHA256.Sum(nil))

	return hash, nil
}

// HashSHA512 calculates the SHA512 checksum of a file.
func HashSHA512(path string) (hash string, err error) {
	var fSize int64
	var f io.ReadCloser

	if f, fSize, err = preCheckFilepath(path); err != nil {
		return hash, err
	}

	defer func() {
		_ = f.Close()
	}()

	if fSize > int64(constMaxFileSize) {
		return hash, NewErrFileTooLarge(path, fSize)
	}

	hashSHA512 := sha512.New()
	_, err = io.Copy(hashSHA512, f)
	if err != nil {
		return hash, fmt.Errorf("couldn't read path (%s) to get SHA512 hash: %w", path, err)
	}

	hash = hex.EncodeToString(hashSHA512.Sum(nil))

	return hash, nil
}

type fileHasher struct {
	enabled bool
	target  *string
	f       func(string) (string, error)
}

func (h fileHasher) hash(file *File) error {
	if !h.enabled {
		return nil
	}
	var res string
	var err error
	if res, err = h.f(file.Path); err == nil {
		*h.target = res
	}
	if err != nil {
		return fmt.Errorf("error calculating checksum for file (%s): %w", file.Path, err)
	}
	return nil
}

func (cfg *config) runEnabledHashers(file *File) error {
	wg := new(sync.WaitGroup)

	if file.Checksums == nil {
		file.Checksums = new(Checksums)
	}

	do := []fileHasher{
		{cfg.sumMD5, &file.Checksums.MD5, HashMD5},
		{cfg.sumSHA1, &file.Checksums.SHA1, HashSHA1},
		{cfg.sumSHA256, &file.Checksums.SHA256, HashSHA256},
		{cfg.sumSHA512, &file.Checksums.SHA512, HashSHA512},
	}
	wg.Add(len(do))
	var errs = make(chan error, len(do))
	for _, v := range do {
		go func(chk fileHasher, fi *File, vwg *sync.WaitGroup) {
			errs <- chk.hash(fi)
			vwg.Done()
		}(v, file, wg)
	}
	wg.Wait()
	close(errs)
	var errsSlice = make([]error, 0, len(do))
	for e := range errs {
		if e != nil {
			errsSlice = append(errsSlice, e)
		}
	}
	return errors.Join(errsSlice...)
}
