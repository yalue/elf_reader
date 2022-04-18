// This package contains functions for reading ELF files.
//
// Example usage, printing section names:
//
//    raw, e := os.ReadFile("/bin/bash")
//    // if e != nil {...}
//    elf, e = elf_reader.ParseELF32File(raw)
//    // if e != nil {...}
//    for i := range elf.Sections {
//        if i != 0 {
//            name, e := elf.GetSectionName(uint16(i))
//            // if e != nil {...}
//            fmt.Printf("Section %d: %s", i, name)
//        }
//    }
package elf_reader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	ELFTypeRelocatable           = 1
	ELFTypeExecutable            = 2
	ELFTypeShared                = 3
	ELFTypeCore                  = 4
	MachineTypeSPARC             = 0x02
	MachineTypeX86               = 0x03
	MachineTypeMIPS              = 0x08
	MachineTypePowerPC           = 0x14
	MachineTypeARM               = 0x28
	MachineTypeAMD64             = 0x3e
	MachineTypeARM64             = 0xb7
	MachineTypeAMDGPU            = 0xe0
	NullSegment                  = 0
	LoadableSegment              = 1
	DynamicLinkingSegment        = 2
	InterpreterSegment           = 3
	NoteSegment                  = 4
	ReservedSegment              = 5
	ProgramHeaderSegment         = 6
	NullSection                  = 0
	BitsSection                  = 1
	SymbolTableSection           = 2
	StringTableSection           = 3
	RelaSection                  = 4
	HashSection                  = 5
	DynamicLinkingTableSection   = 6
	NoteSection                  = 7
	UninitializedSection         = 8
	RelSection                   = 9
	ReservedSection              = 10
	DynamicLoaderSymbolSection   = 11
	GNUHashSection               = 0x6ffffff5
	GNUVersionDefinitionSection  = 0x6ffffffd
	GNUVersionRequirementSection = 0x6ffffffe
	GNUVersionSymbolSection      = 0x6fffffff
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
	case MachineTypeAMDGPU:
		return "AMD GPU"
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
	case 0x6474e551:
		return "stack executability (GNU)"
	case 0x6474e552:
		return "read-only after relocation (GNU)"
	}
	if (t >= 0x70000000) && (t < 0x80000000) {
		return fmt.Sprintf("processor-specific segment: 0x%x", t)
	}
	if (t >= 0x60000000) && (t < 0x70000000) {
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
		return "unused"
	case BitsSection:
		return "bits"
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
		return "note"
	case UninitializedSection:
		return "uninitialized memory"
	case RelSection:
		return "relocation entries"
	case ReservedSection:
		return "reserved"
	case DynamicLoaderSymbolSection:
		return "dynamic loader symbol table"
	case GNUHashSection:
		return "GNU symbol hash table"
	case GNUVersionDefinitionSection:
		return "GNU version definitions"
	case GNUVersionRequirementSection:
		return "GNU version requirements"
	case GNUVersionSymbolSection:
		return "GNU version symbol indices"
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

type SectionHeaderFlags32 uint32

func (f SectionHeaderFlags32) String() string {
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
		"%d bytes in memory, %d in the file, alignment 0x%x. %s", h.Type,
		h.VirtualAddress, h.FileOffset, h.MemorySize, h.FileSize, h.Align,
		h.Flags)
}

// Specifies the format for a single entry for a 32-bit ELF section header.
type ELF32SectionHeader struct {
	Name           uint32
	Type           SectionHeaderType
	Flags          SectionHeaderFlags32
	VirtualAddress uint32
	FileOffset     uint32
	Size           uint32
	LinkedIndex    uint32
	Info           uint32
	Align          uint32
	EntrySize      uint32
}

func (h *ELF32SectionHeader) String() string {
	return fmt.Sprintf("%s section. %d bytes at address 0x%x (offset 0x%x in "+
		"file). Linked to section %d. %s", h.Type, h.Size, h.VirtualAddress,
		h.FileOffset, h.LinkedIndex, h.Flags)
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

// Represents the 32-bit info field in a relocation
type ELF32RelocationInfo uint32

// Returns the 8-bit relocation type in the 32-bit ELF relocation info field.
func (n ELF32RelocationInfo) Type() uint8 {
	return uint8(n)
}

// Returns the 24-bit symbol index.
func (n ELF32RelocationInfo) SymbolIndex() uint32 {
	return uint32(n >> 8)
}

func (n ELF32RelocationInfo) String() string {
	return fmt.Sprintf("type %d, symbol index %d", n.Type(), n.SymbolIndex())
}

type ELF32Relocation interface {
	// Returns the address of the relocation
	Offset() uint32
	// Returns the relocation's type from the info field.
	Type() uint32
	// Returns the symbol index from the info field.
	SymbolIndex() uint32
	// Returns the addent field for the relocation, or 0 if the relocation
	// did not include an addend.
	Addend() int32
	String() string
}

// A relocation without an addend. Satisfies the ELF32Relocation interface.
type ELF32Rel struct {
	Address        uint32
	RelocationInfo ELF32RelocationInfo
}

func (r *ELF32Rel) Offset() uint32 {
	return r.Address
}

func (r *ELF32Rel) Type() uint32 {
	return uint32(r.RelocationInfo.Type())
}

func (r *ELF32Rel) SymbolIndex() uint32 {
	return r.RelocationInfo.SymbolIndex()
}

func (r *ELF32Rel) Addend() int32 {
	return 0
}

func (r *ELF32Rel) String() string {
	return fmt.Sprintf("relocation at address 0x%08x, %s", r.Address,
		r.RelocationInfo)
}

// A relocation with an addend. Also satisfies the ELF32Relocation interface.
type ELF32Rela struct {
	Address        uint32
	RelocationInfo ELF32RelocationInfo
	AddendValue    int32
}

func (r *ELF32Rela) Offset() uint32 {
	return r.Address
}

func (r *ELF32Rela) Type() uint32 {
	return uint32(r.RelocationInfo.Type())
}

func (r *ELF32Rela) SymbolIndex() uint32 {
	return r.RelocationInfo.SymbolIndex()
}

func (r *ELF32Rela) Addend() int32 {
	return r.AddendValue
}

func (r *ELF32Rela) String() string {
	return fmt.Sprintf("relocation at address 0x%08x with addend %d, %s",
		r.Address, r.AddendValue, r.RelocationInfo)
}

// Tracks parsed data for a 32-bit ELF.
type ELF32File struct {
	Header     ELF32Header
	Sections   []ELF32SectionHeader
	Segments   []ELF32ProgramHeader
	Raw        []byte
	Endianness binary.ByteOrder
}

// Returns the bytes of the section at the given index, or an error if one
// occurs.
func (f *ELF32File) GetSectionContent(sectionIndex uint16) ([]byte, error) {
	if int(sectionIndex) >= len(f.Sections) {
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

// Returns the bytes of the segment at the given index, or an error if one
// occurs.
func (f *ELF32File) GetSegmentContent(segmentIndex uint16) ([]byte, error) {
	if int(segmentIndex) > len(f.Segments) {
		return nil, fmt.Errorf("Invalid segment index: %d", segmentIndex)
	}
	start := f.Segments[segmentIndex].FileOffset
	if uint64(start) > uint64(len(f.Raw)) {
		return nil, fmt.Errorf("Bad file offset for segment %d", segmentIndex)
	}
	end := start + f.Segments[segmentIndex].FileSize
	if (uint64(end) > uint64(len(f.Raw))) || (end < start) {
		return nil, fmt.Errorf("Bad size for segment %d", segmentIndex)
	}
	return f.Raw[start:end], nil
}

// Returns the string at the given offset in the string table contained in the
// section at the given section index. Returns an error if one occurs.
func (f *ELF32File) ReadStringTable(sectionIndex uint16, offset uint32) (
	string, error) {
	content, e := f.GetSectionContent(sectionIndex)
	if e != nil {
		return "", fmt.Errorf("Couldn't get string table content: %s", e)
	}
	if f.Sections[sectionIndex].Type != StringTableSection {
		return "", fmt.Errorf("Section %d wasn't a string table", sectionIndex)
	}
	toReturn, e := ReadStringAtOffset(offset, content)
	return string(toReturn), e
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
	name, e := ReadStringAtOffset(f.Sections[sectionIndex].Name, stringContent)
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

// Returns true if the given index is a relocation table.
func (f *ELF32File) IsRelocationTable(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	switch f.Sections[sectionIndex].Type {
	case RelaSection, RelSection:
		return true
	}
	return false
}

// If the given section is a relocation table (type .rel or .rela), this will
// parse and return the relocations.
func (f *ELF32File) GetRelocationTable(sectionIndex uint16) ([]ELF32Relocation,
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
		entryCount := int(header.Size) / binary.Size(&ELF32Rela{})
		toReturnData := make([]ELF32Rela, entryCount)
		e = binary.Read(data, f.Endianness, toReturnData)
		if e != nil {
			return nil, fmt.Errorf("Failed parsing rela table: %s", e)
		}
		// Unfortunately, a slice of structs doesn't equal a slice of
		// relocation interfaces because the interface is implemented on top of
		// the struct pointer rather than the struct itself. So get an array of
		// pointers instead.
		toReturn := make([]ELF32Relocation, entryCount)
		for i := range toReturnData {
			toReturn[i] = &(toReturnData[i])
		}
		return toReturn, nil
	}
	// We're assuming this is a .rel section, since it wasn't .rela
	entryCount := int(header.Size) / binary.Size(&ELF32Rel{})
	toReturnData := make([]ELF32Rel, entryCount)
	e = binary.Read(data, f.Endianness, toReturnData)
	if e != nil {
		return nil, fmt.Errorf("Failed parsing rel table: %s", e)
	}
	toReturn := make([]ELF32Relocation, entryCount)
	for i := range toReturnData {
		toReturn[i] = &(toReturnData[i])
	}
	return toReturn, nil
}

// A constant value indicating the type of an entry in the dynamic table.
type ELF32DynamicTag uint32

func (t ELF32DynamicTag) String() string {
	switch t {
	case 0:
		return "end of dynamic array"
	case 1:
		return "needed library name"
	case 2:
		return "PLT relocations size"
	case 3:
		return "PLT global offset table"
	case 4:
		return "symbol hash table address"
	case 5:
		return "string table address"
	case 6:
		return "symbol table address"
	case 7:
		return "relocation (rela) table address"
	case 8:
		return "relocation (rela) table size"
	case 9:
		return "relocation (rela) entry size"
	case 10:
		return "string table size"
	case 11:
		return "symbol table entry size"
	case 12:
		return "initialization function address"
	case 13:
		return "termination function address"
	case 14:
		return "shared object name"
	case 15:
		return "library search path"
	case 16:
		return "use alternate symbol resolution algorithm"
	case 17:
		return "relocation (rel) table address"
	case 18:
		return "relocation (rel) table size"
	case 19:
		return "relocation (rel) entry size"
	case 20:
		return "PLT relocation type"
	case 21:
		return "debug value"
	case 22:
		return "no read-only relocations allowed"
	case 23:
		return "PLT relocations address"
	case 24:
		return "process relocations now"
	case 25:
		return "initialization function array address"
	case 26:
		return "termination function array address"
	case 27:
		return "initialization function array size"
	case 28:
		return "termination function array size"
	case 0x6ffffef5:
		return "GNU hash table address"
	case 0x6ffffff0:
		return "version symbol table address"
	case 0x6ffffffc:
		return "version definition table address"
	case 0x6ffffffd:
		return "number of version definition table entries"
	case 0x6ffffffe:
		return "version dependency table address"
	case 0x6fffffff:
		return "number of version dependency table entries"
	}
	v := uint32(t)
	if (v < 0x70000000) && (v >= 0x60000000) {
		return fmt.Sprintf("OS-specific dynamic entry 0x%08x", v)
	}
	if (v < 0x80000000) && (v >= 0x70000000) {
		return fmt.Sprintf("processor-specific dynamic entry 0x%08x", v)
	}
	return fmt.Sprintf("unknown dynamic entry 0x%08x", v)
}

// Holds a single entry in a 32-bit ELF .dynamic section. The Value can be
// either an address or a value, depending on the Tag.
type ELF32DynamicEntry struct {
	Tag   ELF32DynamicTag
	Value uint32
}

func (n *ELF32DynamicEntry) String() string {
	return fmt.Sprintf("%s, value 0x%08x", n.Tag, n.Value)
}

// Returns true if the section with the given index is a dynamic linking table.
func (f *ELF32File) IsDynamicSection(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	return f.Sections[sectionIndex].Type == DynamicLinkingTableSection
}

// Parses and returns the dynamic linking table at the given section index. May
// include entries past the end of the actual table, depending on the section
// size, so callers must check for the terminating null entry when referring to
// the returned slice.
func (f *ELF32File) GetDynamicTable(sectionIndex uint16) ([]ELF32DynamicEntry,
	error) {
	if !f.IsDynamicSection(sectionIndex) {
		return nil, fmt.Errorf("Section %d is not a dynamic linking section",
			sectionIndex)
	}
	content, e := f.GetSectionContent(sectionIndex)
	if e != nil {
		return nil, fmt.Errorf("Failed reading dynamic section: %s", e)
	}
	data := bytes.NewReader(content)
	entryCount := f.Sections[sectionIndex].Size /
		uint32(binary.Size(&ELF32DynamicEntry{}))
	toReturn := make([]ELF32DynamicEntry, entryCount)
	e = binary.Read(data, f.Endianness, toReturn)
	if e != nil {
		return nil, fmt.Errorf("Failed parsing dynamic section: %s", e)
	}
	return toReturn, nil
}

// Holds an instance of the ELF32_Verneed structure
type ELF32VersionNeed struct {
	Version   uint16
	Count     uint16
	File      uint32
	AuxOffset uint32
	Next      uint32
}

func (n *ELF32VersionNeed) String() string {
	return fmt.Sprintf("Need version %d of file at string table offset %d",
		n.Version, n.File)
}

// Holds an instance of the ELF32_Vernaux structure
type ELF32VersionNeedAux struct {
	Hash  uint32
	Flags uint16
	Other uint16
	Name  uint32
	Next  uint32
}

func (a *ELF32VersionNeedAux) String() string {
	return fmt.Sprintf("Need definition with hash 0x%08x and name at string "+
		"table offset %d", a.Hash, a.Name)
}

// Returns true if the given section index is a .gnu.version_r section.
func (f *ELF32File) IsVersionRequirementSection(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	return f.Sections[sectionIndex].Type == GNUVersionRequirementSection
}

// Parses and returns a chain of ELF32VersionNeedAux structures, with the first
// structure starting at the given offset in a section's content. Requires the
// number of version aux structures to expect.
func (f *ELF32File) parseVersionNeedAux(content []byte, firstOffset int64,
	count uint16) ([]ELF32VersionNeedAux, error) {
	data := bytes.NewReader(content)
	_, e := data.Seek(firstOffset, io.SeekStart)
	if e != nil {
		return nil, fmt.Errorf("Failed seeking first version aux: %s", e)
	}
	toReturn := make([]ELF32VersionNeedAux, 0, count)
	// Like ParseVersionRequirementSection, we need to get these 1 at a time.
	var current ELF32VersionNeedAux
	var startOffset int64
	for count > 0 {
		startOffset, e = data.Seek(0, io.SeekCurrent)
		if e != nil {
			return nil, fmt.Errorf("Failed getting current offset: %s", e)
		}
		e = binary.Read(data, f.Endianness, &current)
		if e != nil {
			return nil, fmt.Errorf("Failed parsing req. aux struct: %s", e)
		}
		toReturn = append(toReturn, current)
		_, e = data.Seek(startOffset+int64(current.Next), io.SeekStart)
		if e != nil {
			return nil, fmt.Errorf("Failed seeking to next aux struct: %s", e)
		}
		count--
	}
	return toReturn, nil
}

// Reads the dynamic linking table to find the number of entries in the GNU
// version dependency table.
func (f *ELF32File) getVersionDependencyTableSize() (uint32, error) {
	var entries []ELF32DynamicEntry
	var e error
	for i := range f.Sections {
		if !f.IsDynamicSection(uint16(i)) {
			continue
		}
		entries, e = f.GetDynamicTable(uint16(i))
		if e != nil {
			return 0, fmt.Errorf("Failed reading the dynamic table: %s", e)
		}
		break
	}
	if entries == nil {
		return 0, fmt.Errorf("Couldn't find the dynamic table section")
	}
	var toReturn uint32
	found := false
	for i := range entries {
		if entries[i].Tag == 0 {
			break
		}
		if entries[i].Tag != 0x6fffffff {
			continue
		}
		toReturn = entries[i].Value
		found = true
		break
	}
	if !found {
		return 0, fmt.Errorf("The dynamic table didn't contain a number of " +
			"GNU version requirements")
	}
	return toReturn, nil
}

// Returns an array of ELF32VersionNeed structures, in the order they appear in
// a .gnu.version_r section. For each version needed structure, there will be
// an associated slice of version aux structures (which will contain at least
// one entry). If a version requirement section exists but contains no entries,
// this function may return nil, but no error. Returns an error if the section
// type is incorrect or couldn't be parsed for some reason.
func (f *ELF32File) ParseVersionRequirementSection(sectionIndex uint16) (
	[]ELF32VersionNeed, [][]ELF32VersionNeedAux, error) {
	if !f.IsVersionRequirementSection(sectionIndex) {
		return nil, nil, fmt.Errorf("Not a version requirement section: %d",
			sectionIndex)
	}
	content, e := f.GetSectionContent(sectionIndex)
	if e != nil {
		return nil, nil, fmt.Errorf(
			"Failed reading version requirement section: %s", e)
	}
	data := bytes.NewReader(content)
	entryCount, e := f.getVersionDependencyTableSize()
	if e != nil {
		return nil, nil, e
	}
	if entryCount == 0 {
		return nil, nil, nil
	}
	toReturn := make([]ELF32VersionNeed, 0, entryCount)
	auxData := make([][]ELF32VersionNeedAux, 0, entryCount)
	// Unlike other ELF structures, we need to read these version entries one
	// at a time--they may not be directly adjacent.
	var current ELF32VersionNeed
	var currentAux []ELF32VersionNeedAux
	var startOffset int64
	var totalRead uint32
	for {
		startOffset, e = data.Seek(0, io.SeekCurrent)
		if e != nil {
			return nil, nil, fmt.Errorf("Failed getting current offset: %s", e)
		}
		e = binary.Read(data, f.Endianness, &current)
		if e != nil {
			return nil, nil, fmt.Errorf(
				"Failed reading version requirement: %s", e)
		}
		toReturn = append(toReturn, current)
		currentAux, e = f.parseVersionNeedAux(content, startOffset+
			int64(current.AuxOffset), current.Count)
		if e != nil {
			return nil, nil, fmt.Errorf("Failed parsing version requirement "+
				"aux data: %s", e)
		}
		auxData = append(auxData, currentAux)
		totalRead++
		if totalRead >= entryCount {
			break
		}
		// The Next field contains an offset relative to the start of the
		// version need structure.
		_, e = data.Seek(startOffset+int64(current.Next), io.SeekStart)
		if e != nil {
			return nil, nil, fmt.Errorf(
				"Failed seeking to next requirement: %s", e)
		}
	}
	return toReturn, auxData, nil
}

// This is the analogue to the Elf32_Verdef structure, used in GNU version
// definition sections.
type ELF32VersionDef struct {
	Version   uint16
	Flags     uint16
	Index     uint16
	Count     uint16
	Hash      uint32
	AuxOffset uint32
	Next      uint32
}

func (d *ELF32VersionDef) String() string {
	return fmt.Sprintf("Defines version %d (symbol index %d)",
		d.Version, d.Index)
}

// This holds an Elf32_Verdaux structure.
type ELF32VersionDefAux struct {
	Name uint32
	Next uint32
}

func (d *ELF32VersionDefAux) String() string {
	return fmt.Sprintf("Defines version with name at string table offset %d",
		d.Name)
}

func (f *ELF32File) IsVersionDefinitionSection(sectionIndex uint16) bool {
	if int(sectionIndex) >= len(f.Sections) {
		return false
	}
	return f.Sections[sectionIndex].Type == GNUVersionDefinitionSection
}

func (f *ELF32File) getVersionDefinitionTableSize() (uint32, error) {
	var entries []ELF32DynamicEntry
	var e error
	for i := range f.Sections {
		if !f.IsDynamicSection(uint16(i)) {
			continue
		}
		entries, e = f.GetDynamicTable(uint16(i))
		if e != nil {
			return 0, fmt.Errorf("Failed reading the dynamic table: %s", e)
		}
		break
	}
	if entries == nil {
		return 0, fmt.Errorf("Couldn't find the dynamic table section")
	}
	var toReturn uint32
	found := false
	for i := range entries {
		if entries[i].Tag == 0 {
			break
		}
		if entries[i].Tag != 0x6ffffffd {
			continue
		}
		toReturn = entries[i].Value
		found = true
		break
	}
	if !found {
		return 0, fmt.Errorf("The dynamic table didn't contain a number of " +
			"GNU version definitions")
	}
	return toReturn, nil
}

// Parses and returns a chain of ELF32VersionDefAux structures, with the first
// structure starting at the given offset in a section's content. Requires the
// number of definition aux structures to expect.
func (f *ELF32File) parseVersionDefAux(content []byte, firstOffset int64,
	count uint16) ([]ELF32VersionDefAux, error) {
	data := bytes.NewReader(content)
	_, e := data.Seek(firstOffset, io.SeekStart)
	if e != nil {
		return nil, fmt.Errorf("Failed seeking first version aux: %s", e)
	}
	toReturn := make([]ELF32VersionDefAux, 0, count)
	// Like ParseVersionDefintionSection, we need to get these 1 at a time.
	var current ELF32VersionDefAux
	var startOffset int64
	for count > 0 {
		startOffset, e = data.Seek(0, io.SeekCurrent)
		if e != nil {
			return nil, fmt.Errorf("Failed getting current offset: %s", e)
		}
		e = binary.Read(data, f.Endianness, &current)
		if e != nil {
			return nil, fmt.Errorf("Failed parsing defn. aux struct: %s", e)
		}
		toReturn = append(toReturn, current)
		_, e = data.Seek(startOffset+int64(current.Next), io.SeekStart)
		if e != nil {
			return nil, fmt.Errorf("Failed seeking to next aux struct: %s", e)
		}
		count--
	}
	return toReturn, nil
}

// This parses a GNU version definition section with the given index. Returns
// a slice of version definition structs, and a slice of auxiliary structures
// corresponding to each definition. This behaves similarly to
// ParseVersionRequirementSection().
func (f *ELF32File) ParseVersionDefinitionSection(sectionIndex uint16) (
	[]ELF32VersionDef, [][]ELF32VersionDefAux, error) {
	if !f.IsVersionDefinitionSection(sectionIndex) {
		return nil, nil, fmt.Errorf("Not a version definition section: %d",
			sectionIndex)
	}
	content, e := f.GetSectionContent(sectionIndex)
	if e != nil {
		return nil, nil, fmt.Errorf(
			"Failed reading version definition section: %s", e)
	}
	data := bytes.NewReader(content)
	entryCount, e := f.getVersionDefinitionTableSize()
	if e != nil {
		return nil, nil, e
	}
	if entryCount == 0 {
		return nil, nil, nil
	}
	toReturn := make([]ELF32VersionDef, 0, entryCount)
	auxData := make([][]ELF32VersionDefAux, 0, entryCount)
	// Like with version requirements, we need to read these entires one at a
	// time.
	var current ELF32VersionDef
	var currentAux []ELF32VersionDefAux
	var startOffset int64
	var totalRead uint32
	for {
		startOffset, e = data.Seek(0, io.SeekCurrent)
		if e != nil {
			return nil, nil, fmt.Errorf("Failed getting current offset: %s", e)
		}
		e = binary.Read(data, f.Endianness, &current)
		if e != nil {
			return nil, nil, fmt.Errorf(
				"Failed reading version definition: %s", e)
		}
		toReturn = append(toReturn, current)
		currentAux, e = f.parseVersionDefAux(content, startOffset+
			int64(current.AuxOffset), current.Count)
		if e != nil {
			return nil, nil, fmt.Errorf("Failed parsing version definition "+
				"aux data: %s", e)
		}
		auxData = append(auxData, currentAux)
		totalRead++
		if totalRead >= entryCount {
			break
		}
		// The Next field contains an offset relative to the start of the
		// version need structure.
		_, e = data.Seek(startOffset+int64(current.Next), io.SeekStart)
		if e != nil {
			return nil, nil, fmt.Errorf(
				"Failed seeking to next definition: %s", e)
		}
	}
	return toReturn, auxData, nil
}

// Used during initialization to fill in the Segments slice.
func (f *ELF32File) parseProgramHeaders() error {
	offset := f.Header.ProgramHeaderOffset
	if offset >= uint32(len(f.Raw)) {
		return fmt.Errorf("Invalid program header offset: 0x%x", offset)
	}
	data := bytes.NewReader(f.Raw[offset:])
	segments := make([]ELF32ProgramHeader, f.Header.ProgramHeaderEntries)
	e := binary.Read(data, f.Endianness, segments)
	if e != nil {
		return fmt.Errorf("Failed reading program header table: %s", e)
	}
	f.Segments = segments
	return nil
}

// Used during initialization to fill in the Sections slice.
func (f *ELF32File) parseSectionHeaders() error {
	// Don't require a valid section header offset if there are no sections.
	if f.Header.SectionHeaderEntries == 0 {
		f.Sections = nil
		return nil
	}

	offset := f.Header.SectionHeaderOffset
	if offset >= uint32(len(f.Raw)) {
		return fmt.Errorf("Invalid section header offset: 0x%x", offset)
	}
	data := bytes.NewReader(f.Raw[offset:])
	sections := make([]ELF32SectionHeader, f.Header.SectionHeaderEntries)
	e := binary.Read(data, f.Endianness, sections)
	if e != nil {
		return fmt.Errorf("Failed reading section header table: %s", e)
	}
	f.Sections = sections
	return nil
}

// This function must be called in order to re-parse internal data structures
// if the Raw buffer has been updated.
func (f *ELF32File) ReparseData() error {
	var header ELF32Header
	raw := f.Raw
	data := bytes.NewReader(raw)
	var signature uint32
	var e error
	e = binary.Read(data, binary.LittleEndian, &signature)
	if e != nil {
		return fmt.Errorf("Failed reading ELF signature: %s", e)
	}
	if signature != 0x464c457f {
		return fmt.Errorf("Invalid ELF signature: 0x%08x", signature)
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
		return fmt.Errorf("Failed reading ELF32 header: %s", e)
	}
	// This may have been incorrectly reversed if we're big-endian, so we'll
	// copy the correct little-endian version just in case.
	header.Signature = signature
	if header.Class != 1 {
		return fmt.Errorf("ELF class incorrect for 32-bit: %d", header.Class)
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

// Attempts to parse the given data buffer as a 32-bit ELF file. Returns an
// error if the file isn't a 32-bit ELF.
func ParseELF32File(raw []byte) (*ELF32File, error) {
	var toReturn ELF32File
	toReturn.Raw = raw
	e := (&toReturn).ReparseData()
	if e != nil {
		return nil, e
	}
	return &toReturn, nil
}
