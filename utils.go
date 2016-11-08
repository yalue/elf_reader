package elf_reader

// This file contains utility functions which aren't associated with specific
// ELF structures.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Returns a string starting at the offset in the data, or an error if the
// offset is invalid or the string isn't terminated. This can be used to
// extract strings from string table content.
func ReadStringAtOffset(offset uint32, data []byte) ([]byte, error) {
	if offset >= uint32(len(data)) {
		return nil, fmt.Errorf("Invalid string offset: %d", offset)
	}
	endIndex := offset
	for data[endIndex] != 0 {
		endIndex++
		if endIndex >= uint32(len(data)) {
			return nil, fmt.Errorf("Unterminated string starting at offset %d",
				offset)
		}
	}
	return data[offset:endIndex], nil
}

// Calculates the hash value of a given string.
func ELF32Hash(data []byte) uint32 {
	var hash, highBits uint32
	for _, character := range data {
		if character == 0 {
			break
		}
		hash = (hash << 4) + uint32(character)
		highBits = hash & 0xf0000000
		if highBits != 0 {
			hash ^= highBits >> 24
		}
		hash &= ^highBits
	}
	return hash
}

// Outputs the toWrite structure, as binary, at the given offset in the
// destination buffer. May append more data at the end of the destination
// buffer, so this should be used like append(...). Ex:
//     data = []byte("Hi there")
//     toWrite = []byte("!!!")
//     data, e := WriteAtOffset(data, uint64(len(data)), binary.LittleEndian,
//         toWrite)
//
// If the write fails, the original buffer will be returned along with a
// non-nil error.
func WriteAtOffset(destination []byte, offset uint64,
	endianness binary.ByteOrder, toWrite interface{}) ([]byte, error) {
	var b bytes.Buffer
	e := binary.Write(&b, endianness, toWrite)
	if e != nil {
		return destination, e
	}
	neededLength := offset + uint64(b.Len())
	if neededLength > uint64(len(destination)) {
		toAppend := neededLength - uint64(len(destination))
		destination = append(destination, make([]byte, toAppend)...)
	}
	copy(destination[offset:], b.Bytes())
	return destination, nil
}
