// Sandfly entropyscan file utilities to calculate entropy, crypto hashes, etc
package main

/*
This utility will help find packed or encrypted files or processes on a Linux system by calculating the entropy
to see how random they are. Packed or encrypted malware often appears to be a very random executable file and this
utility can help identify potential intrusions.

You can calculate entropy on all files, or limit the search just to Linux ELF executables that have an entropy of
your threshold. Linux processes can be scanned as well automatically.

Sandfly Security produces an agentless endpoint detection and incident response platform (EDR) for Linux. You can
find out more about how it works at: https://www.sandflysecurity.com

MIT License

Copyright (c) 2019-2022 Sandfly Security Ltd.
https://www.sandflysecurity.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Version: 1.1.1
Author: @SandflySecurity
*/

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	// Max file size for entropy, etc. is 2GB
	constMaxFileSize = 2147483648
	// Chunk of data size to read in for entropy calc
	constMaxEntropyChunk = 256000
	// Need 4 bytes to determine basic ELF type
	constMagicNumRead = 4
	// Magic number for basic ELF type
	constMagicNumElf = "7f454c46"
)

type ErrNotRegularFile struct {
	Path string
}

func (e *ErrNotRegularFile) Error() string {
	return fmt.Sprintf("file '%s' is not a regular file", e.Path)
}

func NewErrNotRegularFile(path string) *ErrNotRegularFile {
	return &ErrNotRegularFile{Path: path}
}

type ErrFileTooLarge struct {
	Path string
	Size int64
	Max  int64
}

func (e *ErrFileTooLarge) Error() string {
	return fmt.Sprintf("file size of '%s' is too large (%d bytes) to calculate entropy (max allowed: %d bytes)",
		e.Path, e.Size, e.Max)
}

func NewErrFileTooLarge(path string, size int64) *ErrFileTooLarge {
	return &ErrFileTooLarge{Path: path, Size: size, Max: constMaxFileSize}
}

var ErrNoPath = fmt.Errorf("no path provided")

var elfType []byte

func init() {
	var err error
	if elfType, err = hex.DecodeString(constMagicNumElf); err != nil {
		// this should never happen
		panic(fmt.Errorf("couldn't decode ELF magic number constant: %w", err))
	}
	if len(elfType) > constMagicNumRead {
		// this should never happen
		panic(fmt.Errorf("elf magic number string is longer than magic number read bytes"))
	}
}

func preCheckFilepath(path string) (*os.File, int64, error) {
	if path == "" {
		return nil, 0, ErrNoPath
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't open '%s': %w", path, err)
	}

	fStat, err := f.Stat()
	if err != nil {
		if f != nil {
			_ = f.Close()
		}
		return f, 0, err
	}

	if !fStat.Mode().IsRegular() {
		_ = f.Close()
		return f, 0, NewErrNotRegularFile(path)
	}

	if fStat.Size() == 0 {
		_ = f.Close()
		return f, fStat.Size(), fmt.Errorf("file '%s' is zero size", path)
	}

	return f, fStat.Size(), nil
}

// IsElfType will reead the magic bytes from the passed file and determine if it is an ELF file.
func IsElfType(path string) (isElf bool, err error) {
	var fSize int64
	var f io.ReadCloser

	if f, fSize, err = preCheckFilepath(path); err != nil {
		return false, err
	}

	defer func() {
		_ = f.Close()
	}()

	// Too small to be ELF
	if fSize < constMagicNumRead {
		return false, fmt.Errorf("file '%s' is too small to be an ELF file", path)
	}

	var hexData [constMagicNumRead]byte

	var n int
	if n, err = f.Read(hexData[:]); err != nil {
		return false, fmt.Errorf("couldn't read from '%s': %w", path, err)
	}
	if n != constMagicNumRead {
		return false, fmt.Errorf("couldn't read enough bytes from '%s'", path)
	}

	return bytes.Equal(hexData[:len(elfType)], elfType), nil
}

// Entropy calculates entropy of a file.
func Entropy(path string) (entropy float64, err error) {
	var size int64
	var f io.ReadCloser

	if f, size, err = preCheckFilepath(path); err != nil {
		return 0, err
	}

	defer func() {
		_ = f.Close()
	}()

	if size > int64(constMaxFileSize) {
		return 0, NewErrFileTooLarge(path, size)
	}

	dataBytes := make([]byte, constMaxEntropyChunk)
	byteCounts := make([]int, 256)
	for {
		numBytesRead, readErr := f.Read(dataBytes)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, readErr
		}

		// For each byte of the data that was read, increment the count
		// of that number of bytes seen in the file in our byteCounts
		// array
		for i := 0; i < numBytesRead; i++ {
			byteCounts[int(dataBytes[i])]++
		}
	}

	for i := 0; i < 256; i++ {
		px := float64(byteCounts[i]) / float64(size)
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}

	// Returns rounded to nearest two decimals.
	return math.Round(entropy*100) / 100, nil
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
