package elf_reader

// This file contains code for reading 64-bit ELF files.  It's largely
// analagous to elf32_format.go, with more or less functionality in some
// places (e.g. special section types).

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
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
		execStatus = "not "
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
		"%d bytes in memory, %d in the file, alignment 0x%x. %s", h.Type,
		h.VirtualAddress, h.FileOffset, h.MemorySize, h.FileSize, h.Align,
		h.Flags)
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
	if int(sectionIndex) >= len(f.Sections) {
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

// Returns true if the section at the given index is a string table.
func (f *ELF64File) IsStringTable(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	return f.Sections[sectionIndex].Type == StringTableSection
}

// Returns a slice of strings contained in the string table section at the
// given index. This *includes* the first zero-length string.
func (f *ELF64File) GetStringTable(sectionIndex uint16) ([]string, error) {
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
	// string at the end.
	return strings.Split(string(content[:len(content)-1]), "\x00"), nil
}

// Returns true if the section at the given index is a symbol table.
func (f *ELF64File) IsSymbolTable(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	switch f.Sections[sectionIndex].Type {
	case SymbolTableSection, DynamicLoaderSymbolSection:
		return true
	}
	return false
}

// Holds a symbol table entry for a 64-bit ELF
type ELF64Symbol struct {
	Name         uint32
	Info         ELFSymbolInfo
	Other        uint8
	SectionIndex uint16
	Value        uint64
	Size         uint64
}

func (s *ELF64Symbol) String() string {
	return fmt.Sprintf("%d byte %s symbol. Value: %d, associated section: %d",
		s.Size, s.Info, s.Value, s.SectionIndex)
}

// Parses a symbol table section with the given index, and returns a two
// slices: the symbols, and their corresponding names. Returns an error if the
// given section index is not a valid symbol table.
func (f *ELF64File) GetSymbolTable(sectionIndex uint16) ([]ELF64Symbol,
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
	entryCount := header.Size / uint64(binary.Size(&ELF64Symbol{}))
	symbols := make([]ELF64Symbol, entryCount)
	data := bytes.NewReader(content)
	e = binary.Read(data, f.Endianness, symbols)
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
		tmp, e = ReadStringAtOffset(nameOffset, nameTable)
		if e != nil {
			return nil, nil, fmt.Errorf("Couldn't read name for symbol %d: %s",
				i, e)
		}
		names[i] = string(tmp)
	}
	return symbols, names, nil
}

// Represents the 64-bit info field in a relocation
type ELF64RelocationInfo uint64

// Returns the 32-bit type in the 64-bit ELF relocation info field.
func (n ELF64RelocationInfo) Type() uint32 {
	return uint32(n & 0xffffffff)
}

// Returns the 32-bit symbol table index for a 64-bit ELF relocation info
// field.
func (n ELF64RelocationInfo) SymbolIndex() uint32 {
	return uint32(n >> 32)
}

func (n ELF64RelocationInfo) String() string {
	return fmt.Sprintf("type %d, symbol index %d", n.Type(), n.SymbolIndex())
}

type ELF64Relocation interface {
	// Returns the address of the relocation
	Offset() uint64
	// Returns the relocation type.
	Type() uint32
	// Returns the relocation's symbol index.
	SymbolIndex() uint32
	// Returns the addend field for the relocation, or 0 if the relocation did
	// not include an addend.
	Addend() int64
	String() string
}

// A relocation without an addend. Satisfies the ELF64Relocation interface.
type ELF64Rel struct {
	Address        uint64
	RelocationInfo ELF64RelocationInfo
}

func (r *ELF64Rel) Offset() uint64 {
	return r.Address
}

func (r *ELF64Rel) Type() uint32 {
	return r.RelocationInfo.Type()
}

func (r *ELF64Rel) SymbolIndex() uint32 {
	return r.RelocationInfo.SymbolIndex()
}

func (r *ELF64Rel) Info() ELF64RelocationInfo {
	return r.RelocationInfo
}

func (r *ELF64Rel) Addend() int64 {
	return 0
}

func (r *ELF64Rel) String() string {
	return fmt.Sprintf("relocation at address 0x%016x, %s", r.Address,
		r.RelocationInfo)
}

// A relocation with an addend. Satisfies the ELF64Relocation interface.
type ELF64Rela struct {
	Address        uint64
	RelocationInfo ELF64RelocationInfo
	AddendValue    int64
}

func (r *ELF64Rela) Offset() uint64 {
	return r.Address
}

func (r *ELF64Rela) Info() ELF64RelocationInfo {
	return r.RelocationInfo
}

func (r *ELF64Rela) Type() uint32 {
	return r.RelocationInfo.Type()
}

func (r *ELF64Rela) SymbolIndex() uint32 {
	return r.RelocationInfo.SymbolIndex()
}

func (r *ELF64Rela) Addend() int64 {
	return r.AddendValue
}

func (r *ELF64Rela) String() string {
	return fmt.Sprintf("relocation at address 0x%016x with addend %d, %s",
		r.Address, r.AddendValue, r.RelocationInfo)
}

// Returns true if the given index is a relocation table.
func (f *ELF64File) IsRelocationTable(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	switch f.Sections[sectionIndex].Type {
	case RelaSection, RelSection:
		return true
	}
	return false
}

func (f *ELF64File) GetRelocationTable(sectionIndex uint16) ([]ELF64Relocation,
	error) {
	if !f.IsRelocationTable(sectionIndex) {
		return nil, fmt.Errorf("Section %d is not a relocation table",
			sectionIndex)
	}
	header := &(f.Sections[sectionIndex])
	content, e := f.GetSectionContent(sectionIndex)
	if e != nil {
		return nil, fmt.Errorf("Failed reading relocation table: %s", e)
	}
	data := bytes.NewReader(content)
	if header.Type == RelaSection {
		entryCount := int(header.Size) / binary.Size(&ELF64Rela{})
		toReturnData := make([]ELF64Rela, entryCount)
		e = binary.Read(data, f.Endianness, toReturnData)
		if e != nil {
			return nil, fmt.Errorf("Failed parsing rela table: %s", e)
		}
		// Unfortunately, a slice of structs doesn't equal a slice of
		// relocation interfaces because the interface is implemented on top of
		// the struct pointer rather than the struct itself. So get an array of
		// pointers instead.
		toReturn := make([]ELF64Relocation, entryCount)
		for i := range toReturnData {
			toReturn[i] = &(toReturnData[i])
		}
		return toReturn, nil
	}
	// This wasn't a .rela section, so it must be a .rel section.
	entryCount := int(header.Size) / binary.Size(&ELF64Rel{})
	toReturnData := make([]ELF64Rel, entryCount)
	e = binary.Read(data, f.Endianness, toReturnData)
	if e != nil {
		return nil, fmt.Errorf("Failed parsing rel table: %s", e)
	}
	toReturn := make([]ELF64Relocation, entryCount)
	for i := range toReturnData {
		toReturn[i] = &(toReturnData[i])
	}
	return toReturn, nil
}

// A constant value indicating the type of an entry in the dynamic table.
type ELF64DynamicTag int64

func (t ELF64DynamicTag) String() string {
	// This is cheating, I know, but the values are all the same as far as I
	// can tell.
	return ELF32DynamicTag(t).String()
}

// Holds a single entry in a 64-bit ELF .dynamic section. The Value can be
// either an address or a value, depending on the Tag.
type ELF64DynamicEntry struct {
	Tag   ELF64DynamicTag
	Value uint64
}

func (n *ELF64DynamicEntry) String() string {
	return fmt.Sprintf("%s, value 0x%x", n.Tag, n.Value)
}

// Returns true if the section with the given index is a dynamic linking table.
func (f *ELF64File) IsDynamicSection(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	return f.Sections[sectionIndex].Type == DynamicLinkingTableSection
}

func (f *ELF64File) GetDynamicTable(sectionIndex uint16) ([]ELF64DynamicEntry,
	error) {
	if !f.IsDynamicSection(sectionIndex) {
		return nil, fmt.Errorf("Section %d is not a dynmaic linking section",
			sectionIndex)
	}
	content, e := f.GetSectionContent(sectionIndex)
	if e != nil {
		return nil, fmt.Errorf("Failed reading dynamic section: %s", e)
	}
	data := bytes.NewReader(content)
	entryCount := f.Sections[sectionIndex].Size /
		uint64(binary.Size(&ELF64DynamicEntry{}))
	toReturn := make([]ELF64DynamicEntry, entryCount)
	e = binary.Read(data, f.Endianness, toReturn)
	if e != nil {
		return nil, fmt.Errorf("Failed parsing dynamic section: %s", e)
	}
	return toReturn, nil
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
	// Don't require a valid section header offset if there are no sections.
	if f.Header.SectionHeaderEntries == 0 {
		f.Sections = nil
		return nil
	}

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
