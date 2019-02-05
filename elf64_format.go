package elf_reader

// This file contains code for reading 64-bit ELF files.  It's largely
// analagous to elf32_format.go, with more or less functionality in some
// places (e.g. special section types).

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// The header structure for 64-bit ELF files.
type ELF64Header struct {
	Signature              uint32
	Class                  uint8
	Endianness             uint8
	Version                uint8
	OSABI                  uint8
	EABI                   uint8
	Padding                [7]uint8
	Type                   ELFFileType
	Machine                MachineType
	Version2               uint32
	EntryPoint             uint64
	ProgramHeaderOffset    uint64
	SectionHeaderOffset    uint64
	Flags                  uint32
	HeaderSize             uint16
	ProgramHeaderEntrySize uint16
	ProgramHeaderEntries   uint16
	SectionHeaderEntrySize uint16
	SectionHeaderEntries   uint16
	SectionNamesTable      uint16
}

// Specifies the format for a single entry for a 64-bit ELF section header.
type ELF64SectionHeader struct {
	Name           uint32
	Type           SectionHeaderType
	Flags          SectionHeaderFlags64
	VirtualAddress uint64
	FileOffset     uint64
	Size           uint64
	LinkedIndex    uint32
	Info           uint32
	Align          uint64
	EntrySize      uint64
}

type SectionHeaderFlags64 uint64

func (f SectionHeaderFlags64) String() string {
	var writeStatus, allocStatus, execStatus string
	if (f & 1) == 0 {
		writeStatus = "not "
	}
	if (f & 2) == 0 {
		allocStatus = "not "
	}
	if (f & 4) == 0 {
		allocStatus = "not "
	}
	return fmt.Sprintf("%swritable, %sallocated, %sexecutable", writeStatus,
		allocStatus, execStatus)
}

func (h *ELF64SectionHeader) String() string {
	return fmt.Sprintf("%s section. %d bytes at address 0x%x (offset 0x%x in "+
		"file). Linked to section %d. %s", h.Type, h.Size, h.VirtualAddress,
		h.FileOffset, h.LinkedIndex, h.Flags)
}

// Specifies the format for a single entry for a 64-bit ELF program (segment)
// header.
type ELF64ProgramHeader struct {
	Type            ProgramHeaderType
	Flags           ProgramHeaderFlags
	FileOffset      uint64
	VirtualAddress  uint64
	PhysicalAddress uint64
	FileSize        uint64
	MemorySize      uint64
	Align           uint64
}

func (h *ELF64ProgramHeader) String() string {
	return fmt.Sprintf("%s segment at address 0x%x (offset 0x%x in file). "+
		"%d bytes in memory, %d in the file. %s", h.Type, h.VirtualAddress,
		h.FileOffset, h.MemorySize, h.FileSize, h.Flags)
}

// Tracks parsed data for a 64-bit ELF.
type ELF64File struct {
	Header     ELF64Header
	Sections   []ELF64SectionHeader
	Segments   []ELF64ProgramHeader
	Raw        []byte
	Endianness binary.ByteOrder
}

// Returns the bytes of the section at the given index, or an error if one
// occurs.
func (f *ELF64File) GetSectionContent(sectionIndex uint16) ([]byte, error) {
	if int(sectionIndex) > len(f.Sections) {
		return nil, fmt.Errorf("Invalid section index: %d", sectionIndex)
	}
	start := f.Sections[sectionIndex].FileOffset
	if start > uint64(len(f.Raw)) {
		return nil, fmt.Errorf("Bad file offset for section %d", sectionIndex)
	}
	end := start + f.Sections[sectionIndex].Size
	if (end > uint64(len(f.Raw))) || (end < start) {
		return nil, fmt.Errorf("Bad size for section %d", sectionIndex)
	}
	return f.Raw[start:end], nil
}

// Returns the name of the section at the given index in the section table, or
// an error if one occurs.
func (f *ELF64File) GetSectionName(sectionIndex uint16) (string, error) {
	if sectionIndex == 0 {
		return "", fmt.Errorf("The null (0-index) section doesn't have a name")
	}
	stringContent, e := f.GetSectionContent(f.Header.SectionNamesTable)
	if e != nil {
		return "", fmt.Errorf("Couldn't read section names table: %s", e)
	}
	name, e := ReadStringAtOffset(f.Sections[sectionIndex].Name, stringContent)
	if e != nil {
		return "", fmt.Errorf("Couldn't read section name: %s", e)
	}
	return string(name), nil
}

// Used during initialization to fill in the Segments slice.
func (f *ELF64File) parseProgramHeaders() error {
	offset := f.Header.ProgramHeaderOffset
	if offset >= uint64(len(f.Raw)) {
		return fmt.Errorf("Invalid program header offset: 0x%x", offset)
	}
	data := bytes.NewReader(f.Raw[offset:])
	segments := make([]ELF64ProgramHeader, f.Header.ProgramHeaderEntries)
	e := binary.Read(data, f.Endianness, segments)
	if e != nil {
		return fmt.Errorf("Failed reading program header table: %s", e)
	}
	f.Segments = segments
	return nil
}

// Used during initialization to fill in the Sections slice.
func (f *ELF64File) parseSectionHeaders() error {
	offset := f.Header.SectionHeaderOffset
	if offset >= uint64(len(f.Raw)) {
		return fmt.Errorf("Invalid section header offset: 0x%x", offset)
	}
	data := bytes.NewReader(f.Raw[offset:])
	sections := make([]ELF64SectionHeader, f.Header.SectionHeaderEntries)
	e := binary.Read(data, f.Endianness, sections)
	if e != nil {
		return fmt.Errorf("Failed reading section header table: %s", e)
	}
	f.Sections = sections
	return nil
}

// This function must be called in order to re-parse internal data structures
// if the Raw buffer has been updated.
func (f *ELF64File) ReparseData() error {
	var header ELF64Header
	raw := f.Raw
	data := bytes.NewReader(raw)
	var signature uint32
	var e error
	e = binary.Read(data, binary.LittleEndian, &signature)
	if e != nil {
		return fmt.Errorf("Failed reading ELF signature: %s", e)
	}
	// Rewind the input back to the beginning.
	data = bytes.NewReader(raw)
	if len(raw) < 6 {
		return fmt.Errorf("Insufficient size for an ELF file")
	}
	var endianness binary.ByteOrder
	if raw[5] != 1 {
		if raw[5] != 2 {
			return fmt.Errorf("Invalid encoding/endianness: %d", raw[5])
		}
		endianness = binary.BigEndian
	} else {
		endianness = binary.LittleEndian
	}
	e = binary.Read(data, endianness, &header)
	if e != nil {
		return fmt.Errorf("Failed reading ELF64 header: %s", e)
	}
	// The signature may have been incorrectly read backwards if we're reading
	// a big-endian ELF, so we'll copy the correct little endian version to
	// make sure it's the expected value later.
	header.Signature = signature
	if header.Class != 2 {
		return fmt.Errorf("ELF class incorrect for 64-bit: %d", header.Class)
	}
	f.Header = header
	f.Endianness = endianness
	e = f.parseProgramHeaders()
	if e != nil {
		return e
	}
	e = f.parseSectionHeaders()
	if e != nil {
		return e
	}
	return nil
}

func ParseELF64File(raw []byte) (*ELF64File, error) {
	var toReturn ELF64File
	toReturn.Raw = raw
	e := (&toReturn).ReparseData()
	if e != nil {
		return nil, e
	}
	return &toReturn, nil
}
