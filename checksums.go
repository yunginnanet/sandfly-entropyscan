package main

import "sync"

// Checksums is a struct that encapsulates all checksums of a [File].
type Checksums struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
	mu     sync.RWMutex
}

// Get returns the checksum of the given [HashType].
func (c *Checksums) Get(ht HashType) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	switch ht {
	case HashTypeMD5:
		return c.MD5
	case HashTypeSHA1:
		return c.SHA1
	case HashTypeSHA256:
		return c.SHA256
	case HashTypeSHA512:
		return c.SHA512
	default:
		return ""
	}
}

// Set sets the checksum of the given [HashType].
func (c *Checksums) Set(ht HashType, val string) {
	c.mu.Lock()
	switch ht {
	case HashTypeMD5:
		c.MD5 = val
	case HashTypeSHA1:
		c.SHA1 = val
	case HashTypeSHA256:
		c.SHA256 = val
	case HashTypeSHA512:
		c.SHA512 = val
	default:
		panic("unknown hash type")
	}
	c.mu.Unlock()
}
