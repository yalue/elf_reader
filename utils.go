package elf_reader

// This file contains utility functions which aren't associated with specific
// ELF structures.

import (
	"fmt"
)

// Returns a string starting at the offset in the data, or an error if the
// offset is invalid or the string isn't terminated.
func readStringAtOffset(offset uint32, data []byte) ([]byte, error) {
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
