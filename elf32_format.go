// This package contains functions for reading ELF files.
package elf_reader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	ELFTypeRelocatable         = 1
	ELFTypeExecutable          = 2
	ELFTypeShared              = 3
	ELFTypeCore                = 4
	MachineTypeSPARC           = 0x02
	MachineTypeX86             = 0x03
	MachineTypeMIPS            = 0x08
	MachineTypePowerPC         = 0x14
	MachineTypeARM             = 0x28
	MachineTypeAMD64           = 0x3e
	MachineTypeARM64           = 0xb7
	NullSegment                = 0
	LoadableSegment            = 1
	DynamicLinkingSegment      = 2
	InterpreterSegment         = 3
	NoteSegment                = 4
	ReservedSegment            = 5
	ProgramHeaderSegment       = 6
	NullSection                = 0
	BitsSection                = 1
	SymbolTableSection         = 2
	StringTableSection         = 3
	RelaSection                = 4
	HashSection                = 5
	DynamicLinkingTableSection = 6
	NoteSection                = 7
	UninitializedSection       = 8
	RelSection                 = 9
	ReservedSection            = 10
	DynamicLoaderSymbolSection = 11
)

type ELFFileType uint16

func (t ELFFileType) String() string {
	switch t {
	case ELFTypeRelocatable:
		return "relocatable file"
	case ELFTypeExecutable:
		return "executable file"
	case ELFTypeShared:
		return "shared file"
	case ELFTypeCore:
		return "core file"
	}
	return fmt.Sprintf("unkown ELF type: %d", t)
}

type MachineType uint16

func (t MachineType) String() string {
	switch t {
	case 0:
		return "unspecified machine type"
	case MachineTypeSPARC:
		return "SPARC"
	case MachineTypeX86:
		return "x86"
	case MachineTypeMIPS:
		return "MIPS"
	case MachineTypePowerPC:
		return "PowerPC"
	case MachineTypeARM:
		return "ARM"
	case MachineTypeAMD64:
		return "AMD64"
	case MachineTypeARM64:
		return "ARM64"
	}
	return fmt.Sprintf("unknown machine type: 0x%02x", uint16(t))
}

type ProgramHeaderType uint32

func (ht ProgramHeaderType) String() string {
	// Avoid printf recursion by explicitly casting this to a uint32
	t := uint32(ht)
	switch t {
	case NullSegment:
		return "unused segment"
	case LoadableSegment:
		return "loadable segment"
	case DynamicLinkingSegment:
		return "dynamic linking tables"
	case InterpreterSegment:
		return "interpreter path name segment"
	case NoteSegment:
		return "note segment"
	case ReservedSegment:
		return "reserved segment type"
	case ProgramHeaderSegment:
		return "program header table"
	}
	if t >= 0x80000000 {
		return fmt.Sprintf("invalid segment type: 0x%x", t)
	}
	if t >= 0x70000000 {
		return fmt.Sprintf("processor-specific segment: 0x%x", t)
	}
	if t >= 0x60000000 {
		return fmt.Sprintf("OS-specific segment: 0x%x", t)
	}
	return fmt.Sprintf("invalid segment type 0x%x", t)
}

type ProgramHeaderFlags uint32

func (t ProgramHeaderFlags) String() string {
	var readStatus, writeStatus, execStatus string
	if (t & 1) == 0 {
		execStatus = "not "
	}
	if (t & 2) == 0 {
		writeStatus = "not "
	}
	if (t & 4) == 0 {
		readStatus = "not "
	}
	return fmt.Sprintf("%sreadable, %swritable, %sexecutable", readStatus,
		writeStatus, execStatus)
}

type SectionHeaderType uint32

func (ht SectionHeaderType) String() string {
	// Like ProgramHeaderType, prevent printf recursion.
	t := uint32(ht)
	switch t {
	case NullSection:
		return "unused section"
	case BitsSection:
		return "bits section"
	case SymbolTableSection:
		return "symbol table"
	case StringTableSection:
		return "string table"
	case RelaSection:
		return "relocation entries with addends"
	case HashSection:
		return "symbol hash table"
	case DynamicLinkingTableSection:
		return "dynamic linking table"
	case NoteSection:
		return "note section"
	case UninitializedSection:
		return "uninitialized memory"
	case RelSection:
		return "relocation entries"
	case ReservedSection:
		return "reserved section"
	case DynamicLoaderSymbolSection:
		return "dynamic loader symbol table"
	}
	if t >= 0x80000000 {
		return fmt.Sprintf("invalid section type: 0x%x", t)
	}
	if t >= 0x70000000 {
		return fmt.Sprintf("processor-specific section type: 0x%x", t)
	}
	if t >= 0x60000000 {
		return fmt.Sprintf("OS-specific section type: 0x%x", t)
	}
	return fmt.Sprintf("invalid section type: 0x%x", t)
}

type SectionHeaderFlags uint32

func (f SectionHeaderFlags) String() string {
	var writeStatus, allocStatus, execStatus string
	if (f & 1) == 0 {
		writeStatus = "not "
	}
	if (f & 2) == 0 {
		allocStatus = "not "
	}
	if (f & 4) == 0 {
		execStatus = "not "
	}
	return fmt.Sprintf("%swritable, %sallocated, %sexecutable", writeStatus,
		allocStatus, execStatus)
}

// The header structure for 32-bit ELF files.
type ELF32Header struct {
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
	EntryPoint             uint32
	ProgramHeaderOffset    uint32
	SectionHeaderOffset    uint32
	Flags                  uint32
	HeaderSize             uint16
	ProgramHeaderEntrySize uint16
	ProgramHeaderEntries   uint16
	SectionHeaderEntrySize uint16
	SectionHeaderEntries   uint16
	SectionNamesTable      uint16
}

func (h *ELF32Header) String() string {
	return fmt.Sprintf("32-bit ELF file for %s", h.Machine)
}

// Specifies the format for a single entry for a 32-bit ELF program (segment)
// header.
type ELF32ProgramHeader struct {
	Type            ProgramHeaderType
	FileOffset      uint32
	VirtualAddress  uint32
	PhysicalAddress uint32
	FileSize        uint32
	MemorySize      uint32
	Flags           ProgramHeaderFlags
	Align           uint32
}

func (h *ELF32ProgramHeader) String() string {
	return fmt.Sprintf("%s segment at address 0x%x (offset 0x%x in file). "+
		"%d bytes in memory, %d in the file. %s", h.Type, h.VirtualAddress,
		h.FileOffset, h.MemorySize, h.FileSize, h.Flags)
}

// Specifies the format for a single entry for a 32-bit ELF section header.
type ELF32SectionHeader struct {
	Name           uint32
	Type           SectionHeaderType
	Flags          SectionHeaderFlags
	VirtualAddress uint32
	FileOffset     uint32
	Size           uint32
	LinkedIndex    uint32
	Info           uint32
	Align          uint32
	EntrySize      uint32
}

func (h *ELF32SectionHeader) String() string {
	return fmt.Sprintf("%s section at address 0x%x (offset 0x%x in file). "+
		"%d bytes. %s", h.Type, h.VirtualAddress, h.FileOffset, h.Size,
		h.Flags)
}

// Represents the 8-bit info field in symbol table entries
type ELFSymbolInfo uint8

func (n ELFSymbolInfo) Binding() uint8 {
	return uint8(n >> 4)
}

func (n ELFSymbolInfo) SymbolType() uint8 {
	return uint8(n & 0xf)
}

func (n ELFSymbolInfo) String() string {
	binding := n.Binding()
	bindingString := ""
	switch {
	case binding == 0:
		bindingString = "local binding"
	case binding == 1:
		bindingString = "weak binding"
	case binding == 2:
		bindingString = "global binding"
	case (binding >= 10) && (binding <= 12):
		bindingString = fmt.Sprintf("os-specific binding %d", binding)
	case (binding >= 13) && (binding <= 15):
		bindingString = fmt.Sprintf("processor-specific binding %d", binding)
	default:
		bindingString = fmt.Sprintf("unknown binding %d", binding)
	}
	t := n.SymbolType()
	typeString := ""
	switch {
	case t == 0:
		typeString = "no type"
	case t == 1:
		typeString = "object"
	case t == 2:
		typeString = "function"
	case t == 3:
		typeString = "section"
	case t == 4:
		typeString = "file"
	case (t >= 10) && (t <= 12):
		typeString = fmt.Sprintf("os-specific type %d", t)
	case (t >= 13) && (t <= 15):
		typeString = fmt.Sprintf("processor-specific type %d", t)
	default:
		typeString = fmt.Sprintf("unknown type %d", t)
	}
	return fmt.Sprintf("%s, %s", typeString, bindingString)
}

// Holds a symbol table entry for a 32-bit ELF
type ELF32Symbol struct {
	Name         uint32
	Value        uint32
	Size         uint32
	Info         ELFSymbolInfo
	Other        uint8
	SectionIndex uint16
}

func (s *ELF32Symbol) String() string {
	return fmt.Sprintf("%d byte %s symbol. Value: %d, associated section: %d",
		s.Size, s.Info, s.Value, s.SectionIndex)
}

// Tracks parsed data for a 32-bit ELF.
type ELF32File struct {
	Header   ELF32Header
	Sections []ELF32SectionHeader
	Segments []ELF32ProgramHeader
	Raw      []byte
}

// Returns the bytes of the section at the given index, or an error if one
// occurs.
func (f *ELF32File) GetSectionContent(sectionIndex uint16) ([]byte, error) {
	if int(sectionIndex) > len(f.Sections) {
		return nil, fmt.Errorf("Invalid section index: %d", sectionIndex)
	}
	start := f.Sections[sectionIndex].FileOffset
	if int(start) > len(f.Raw) {
		return nil, fmt.Errorf("Bad section file offset")
	}
	end := start + f.Sections[sectionIndex].Size
	if int(end) > len(f.Raw) {
		return nil, fmt.Errorf("Bad section size")
	}
	return f.Raw[start:end], nil
}

// Returns the name of the section at the given index in the section table, or
// an error if one occurs.
func (f *ELF32File) GetSectionName(sectionIndex uint16) (string, error) {
	if sectionIndex == 0 {
		return "", fmt.Errorf("The null (0-index) section doesn't have a name")
	}
	stringContent, e := f.GetSectionContent(f.Header.SectionNamesTable)
	if e != nil {
		return "", fmt.Errorf("Couldn't read section names table: %s", e)
	}
	name, e := readStringAtOffset(f.Sections[sectionIndex].Name, stringContent)
	if e != nil {
		return "", fmt.Errorf("Couldn't read section name: %s", e)
	}
	return string(name), nil
}

// Returns true if the section at the given index is a string table.
func (f *ELF32File) IsStringTable(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	return f.Sections[sectionIndex].Type == StringTableSection
}

// Returns true if the section at the given index is a symbol table.
func (f *ELF32File) IsSymbolTable(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	switch f.Sections[sectionIndex].Type {
	case SymbolTableSection, DynamicLoaderSymbolSection:
		return true
	}
	return false
}

// Parses a symbol table section with the given index, and a slice of the names
// of each symbol. The parsed symbols and names will be in the same order.
// Returns an error if the given index doesn't contain a valid symbol table.
func (f *ELF32File) GetSymbolTable(sectionIndex uint16) ([]ELF32Symbol,
	[]string, error) {
	if !f.IsSymbolTable(sectionIndex) {
		return nil, nil, fmt.Errorf("Section %d is not a symbol table",
			sectionIndex)
	}
	content, e := f.GetSectionContent(sectionIndex)
	if e != nil {
		return nil, nil, e
	}
	header := &(f.Sections[sectionIndex])
	nameTable, e := f.GetSectionContent(uint16(header.LinkedIndex))
	if e != nil {
		return nil, nil, fmt.Errorf("Failed reading symbol name table: %s", e)
	}
	entryCount := header.Size / uint32(binary.Size(&ELF32Symbol{}))
	symbols := make([]ELF32Symbol, entryCount)
	data := bytes.NewReader(content)
	e = binary.Read(data, binary.LittleEndian, symbols)
	if e != nil {
		return nil, nil, fmt.Errorf("Failed parsing symbol table: %s", e)
	}
	names := make([]string, entryCount)
	var nameOffset uint32
	var tmp []byte
	for i := range symbols {
		nameOffset = symbols[i].Name
		// It's okay for a symbol name to be at offset 0, they're just empty
		// strings.
		if nameOffset == 0 {
			names[i] = ""
			continue
		}
		tmp, e = readStringAtOffset(nameOffset, nameTable)
		if e != nil {
			return nil, nil, fmt.Errorf("Couldn't read name for symbol %d: %s",
				i, e)
		}
		names[i] = string(tmp)
	}
	return symbols, names, nil
}

// Returns a slice of strings contained in the string table at the given index.
// This *includes* the first zero-length string.
func (f *ELF32File) GetStringTable(sectionIndex uint16) ([]string, error) {
	if !f.IsStringTable(sectionIndex) {
		return nil, fmt.Errorf("Section %d is not a string table",
			sectionIndex)
	}
	content, e := f.GetSectionContent(sectionIndex)
	if e != nil {
		return nil, fmt.Errorf("Failed reading string table: %s", e)
	}
	if content[len(content)-1] != 0 {
		return nil, fmt.Errorf("The string table wasn't null-terminated")
	}
	// Trim the last null byte from the table to avoid having an extra empty
	// string in the slice we return.
	return strings.Split(string(content[:len(content)-1]), "\x00"), nil
}

// TODO (next): Test dumping symbols. Parse relocations next, followed by
// dynamic linking tables. Still keep track of string references!

// Used during initialization to fill in the Segments slice.
func (f *ELF32File) parseProgramHeaders() error {
	offset := f.Header.ProgramHeaderOffset
	if offset >= uint32(len(f.Raw)) {
		return fmt.Errorf("Invalid program header offset: 0x%x", offset)
	}
	data := bytes.NewReader(f.Raw[offset:])
	segments := make([]ELF32ProgramHeader, f.Header.ProgramHeaderEntries)
	e := binary.Read(data, binary.LittleEndian, segments)
	if e != nil {
		return fmt.Errorf("Failed reading program header table: %s", e)
	}
	f.Segments = segments
	return nil
}

// Used during initialization to fill in the Sections slice.
func (f *ELF32File) parseSectionHeaders() error {
	offset := f.Header.SectionHeaderOffset
	if offset >= uint32(len(f.Raw)) {
		return fmt.Errorf("Invalid section header offset: 0x%x", offset)
	}
	data := bytes.NewReader(f.Raw[offset:])
	sections := make([]ELF32SectionHeader, f.Header.SectionHeaderEntries)
	e := binary.Read(data, binary.LittleEndian, sections)
	if e != nil {
		return fmt.Errorf("Failed reading section header table: %s", e)
	}
	f.Sections = sections
	return nil
}

// Attempts to parse the given data buffer as a 32-bit ELF file. Returns an
// error if the file isn't a 32-bit, little-endian ELF.
func ParseELF32File(raw []byte) (*ELF32File, error) {
	var header ELF32Header
	data := bytes.NewReader(raw)
	e := binary.Read(data, binary.LittleEndian, &header)
	if e != nil {
		return nil, fmt.Errorf("Failed reading ELF32 header: %s", e)
	}
	if header.Signature != 0x464c457f {
		return nil, fmt.Errorf("Invalid ELF signature: 0x%08x",
			header.Signature)
	}
	if header.Class != 1 {
		return nil, fmt.Errorf("ELF class incorrect for 32-bit: %d",
			header.Class)
	}
	if header.Endianness != 1 {
		return nil, fmt.Errorf("Big-Endian ELF files aren't supported yet")
	}
	var toReturn ELF32File
	toReturn.Header = header
	toReturn.Raw = raw
	e = (&toReturn).parseProgramHeaders()
	if e != nil {
		return nil, e
	}
	e = (&toReturn).parseSectionHeaders()
	if e != nil {
		return nil, e
	}
	return &toReturn, nil
}
