package elf_reader

// This file contains the definition for an ELF file interface that can be used
// to read either 32- or 64-bit ELF files. Boilerplate wrappers for
// implementing this interface are also kept in this file.

import (
	"fmt"
)

// This is a 32- or 64-bit agnostic way of reading an ELF file. If needed, one
// can use type assertions to convert instances of this interface into either
// instances of *ELF64File or *ELF32File.
type ELFFile interface {
	// Returns the number of sections defined in the ELF file.
	GetSectionCount() (uint16, error)
	// Returns the number of segments (program headers) defined in the ELF
	// file.
	GetSegmentCount() (uint16, error)
	// Returns the name of the section at the given index.
	GetSectionName(index uint16) (string, error)
	// Returns the content of the section at the given index.
	GetSectionContent(index uint16) ([]byte, error)
	// Returns an interface that can be used to access the header metadata for
	// the section at the given index.
	GetSectionHeader(index uint16) (ELFSectionHeader, error)
	// Returns an interface that can be used to access the header metadata for
	// the program header (segment) at the given index.
	GetProgramHeader(index uint16) (ELFProgramHeader, error)
	// Returns true if the section at the given index is a string table.
	IsStringTable(index uint16) bool
	// Returns a slice of strings from the string table in the given section
	// index.
	GetStringTable(index uint16) ([]string, error)
	// Returns true if the section at the given index is a symbol table.
	IsSymbolTable(index uint16) bool
	// Parses the symbol table in the section at the given index, and returns
	// a slice of symbols in it. The slice of strings is the list of symbol
	// names, in the same order as the symbols themselves.
	GetSymbols(index uint16) ([]ELFSymbol, []string, error)
	// Returns true if the section at the given index is a relocation table.
	IsRelocationTable(index uint16) bool
	// Parses the relocation table in the section at the given index, and
	// returns a slice of the relocations contained in it.
	GetRelocations(index uint16) ([]ELFRelocation, error)
	// Returns true if the section at the given index is a dynamic table.
	IsDynamicSection(index uint16) bool
	// Parses and returns the dynamic linking table at the given section index.
	// This may return entries past the end of the actual table, depending on
	// the section size, so callers must check for the terminating null entry
	// when referring to the returned slice.
	DynamicEntries(intex uint16) ([]ELFDynamicEntry, error)
}

func (f *ELF64File) GetSectionCount() (uint16, error) {
	return uint16(len(f.Sections)), nil
}

func (f *ELF32File) GetSectionCount() (uint16, error) {
	return uint16(len(f.Sections)), nil
}

func (f *ELF64File) GetSegmentCount() (uint16, error) {
	return uint16(len(f.Segments)), nil
}

func (f *ELF32File) GetSegmentCount() (uint16, error) {
	return uint16(len(f.Segments)), nil
}

func (f *ELF64File) GetSectionHeader(index uint16) (ELFSectionHeader, error) {
	if int(index) >= len(f.Sections) {
		return nil, fmt.Errorf("Invalid section index: %d", index)
	}
	return &(f.Sections[index]), nil
}

func (f *ELF32File) GetSectionHeader(index uint16) (ELFSectionHeader, error) {
	if int(index) >= len(f.Sections) {
		return nil, fmt.Errorf("Invalid section index: %d", index)
	}
	return &(f.Sections[index]), nil
}

func (f *ELF64File) GetProgramHeader(index uint16) (ELFProgramHeader, error) {
	if int(index) >= len(f.Segments) {
		return nil, fmt.Errorf("Invalid segment index: %d", index)
	}
	return &(f.Segments[index]), nil
}

func (f *ELF32File) GetProgramHeader(index uint16) (ELFProgramHeader, error) {
	if int(index) >= len(f.Segments) {
		return nil, fmt.Errorf("Invalid segment index: %d", index)
	}
	return &(f.Segments[index]), nil
}

func (f *ELF64File) GetSymbols(index uint16) ([]ELFSymbol, []string, error) {
	table, names, e := f.GetSymbolTable(index)
	if e != nil {
		return nil, nil, e
	}
	// We need to convert the table into a list of pointers to satisfy the
	// ELFSymbol interface.
	toReturn := make([]ELFSymbol, len(table))
	for i := range table {
		toReturn[i] = &(table[i])
	}
	return toReturn, names, nil
}

func (f *ELF32File) GetSymbols(index uint16) ([]ELFSymbol, []string, error) {
	table, names, e := f.GetSymbolTable(index)
	if e != nil {
		return nil, nil, e
	}
	toReturn := make([]ELFSymbol, len(table))
	for i := range table {
		toReturn[i] = &(table[i])
	}
	return toReturn, names, nil
}

func (f *ELF64File) GetRelocations(index uint16) ([]ELFRelocation, error) {
	// The 64-bit ELF relocation table already satisfies the ELFRelocation
	// interface.
	values, e := f.GetRelocationTable(index)
	if e != nil {
		return nil, e
	}
	toReturn := make([]ELFRelocation, len(values))
	for i := range values {
		toReturn[i] = values[i]
	}
	return toReturn, nil
}

func (f *ELF32File) GetRelocations(index uint16) ([]ELFRelocation, error) {
	// We need to convert this table into the 64-bit format...
	table32, e := f.GetRelocationTable(index)
	if e != nil {
		return nil, e
	}
	toReturn := make([]ELFRelocation, len(table32))
	for i := range table32 {
		original := table32[i]
		relocationType := original.Type()
		symbolIndex := original.SymbolIndex()
		newInfo := ELF64RelocationInfo(relocationType)
		newInfo |= ELF64RelocationInfo(symbolIndex) << 32
		toReturn[i] = &ELF64Rela{
			Address:        uint64(original.Offset()),
			RelocationInfo: newInfo,
			AddendValue:    int64(original.Addend()),
		}
	}
	return toReturn, nil
}

func (f *ELF64File) DynamicEntries(index uint16) ([]ELFDynamicEntry, error) {
	table, e := f.GetDynamicTable(index)
	if e != nil {
		return nil, e
	}
	// Same story as with GetSymbols... we need a slice of interfaces here.
	toReturn := make([]ELFDynamicEntry, len(table))
	for i := range table {
		toReturn[i] = &(table[i])
	}
	return toReturn, nil
}

func (f *ELF32File) DynamicEntries(index uint16) ([]ELFDynamicEntry, error) {
	table, e := f.GetDynamicTable(index)
	if e != nil {
		return nil, e
	}
	// Same story as with GetSymbols... we need a slice of interfaces here.
	toReturn := make([]ELFDynamicEntry, len(table))
	for i := range table {
		toReturn[i] = &(table[i])
	}
	return toReturn, nil
}

// This is a 32- or 64-bit agnostic interface for accessing an ELF section's
// flags. Can be converted using type assertions into either
// SectionHeaderFlags64 or SectionHeaderFlags32 values.
type ELFSectionFlags interface {
	Executable() bool
	Allocated() bool
	Writable() bool
	String() string
}

func (f SectionHeaderFlags32) Executable() bool {
	return (f & 4) != 0
}

func (f SectionHeaderFlags32) Allocated() bool {
	return (f & 2) != 0
}

func (f SectionHeaderFlags32) Writable() bool {
	return (f & 1) != 0
}

func (f SectionHeaderFlags64) Executable() bool {
	return (f & 4) != 0
}

func (f SectionHeaderFlags64) Allocated() bool {
	return (f & 2) != 0
}

func (f SectionHeaderFlags64) Writable() bool {
	return (f & 1) != 0
}

// This is a 32- or 64-bit agnostic way of accessing an ELF section header.
type ELFSectionHeader interface {
	GetType() SectionHeaderType
	GetFlags() ELFSectionFlags
	GetVirtualAddress() uint64
	GetFileOffset() uint64
	GetSize() uint64
	GetLinkedIndex() uint32
	GetInfo() uint32
	GetAlignment() uint64
	GetEntrySize() uint64
	String() string
}

func (h *ELF64SectionHeader) GetType() SectionHeaderType {
	return h.Type
}

func (h *ELF64SectionHeader) GetFlags() ELFSectionFlags {
	return h.Flags
}

func (h *ELF64SectionHeader) GetVirtualAddress() uint64 {
	return h.VirtualAddress
}

func (h *ELF64SectionHeader) GetFileOffset() uint64 {
	return h.FileOffset
}

func (h *ELF64SectionHeader) GetSize() uint64 {
	return h.Size
}

func (h *ELF64SectionHeader) GetLinkedIndex() uint32 {
	return h.LinkedIndex
}

func (h *ELF64SectionHeader) GetInfo() uint32 {
	return h.Info
}

func (h *ELF64SectionHeader) GetAlignment() uint64 {
	return h.Align
}

func (h *ELF64SectionHeader) GetEntrySize() uint64 {
	return h.EntrySize
}

func (h *ELF32SectionHeader) GetType() SectionHeaderType {
	return h.Type
}

func (h *ELF32SectionHeader) GetFlags() ELFSectionFlags {
	return h.Flags
}

func (h *ELF32SectionHeader) GetVirtualAddress() uint64 {
	return uint64(h.VirtualAddress)
}

func (h *ELF32SectionHeader) GetFileOffset() uint64 {
	return uint64(h.FileOffset)
}

func (h *ELF32SectionHeader) GetSize() uint64 {
	return uint64(h.Size)
}

func (h *ELF32SectionHeader) GetLinkedIndex() uint32 {
	return h.LinkedIndex
}

func (h *ELF32SectionHeader) GetInfo() uint32 {
	return h.Info
}

func (h *ELF32SectionHeader) GetAlignment() uint64 {
	return uint64(h.Align)
}

func (h *ELF32SectionHeader) GetEntrySize() uint64 {
	return uint64(h.EntrySize)
}

// This is a 32- or 64-bit agnostic way of accessing an ELF program header.
type ELFProgramHeader interface {
	GetType() ProgramHeaderType
	GetFlags() ProgramHeaderFlags
	GetFileOffset() uint64
	GetVirtualAddress() uint64
	GetPhysicalAddress() uint64
	GetFileSize() uint64
	GetMemorySize() uint64
	GetAlignment() uint64
	String() string
}

func (h *ELF64ProgramHeader) GetType() ProgramHeaderType {
	return h.Type
}

func (h *ELF64ProgramHeader) GetFlags() ProgramHeaderFlags {
	return h.Flags
}

func (h *ELF64ProgramHeader) GetFileOffset() uint64 {
	return h.FileOffset
}

func (h *ELF64ProgramHeader) GetVirtualAddress() uint64 {
	return h.VirtualAddress
}

func (h *ELF64ProgramHeader) GetPhysicalAddress() uint64 {
	return h.PhysicalAddress
}

func (h *ELF64ProgramHeader) GetFileSize() uint64 {
	return h.FileSize
}

func (h *ELF64ProgramHeader) GetMemorySize() uint64 {
	return h.MemorySize
}

func (h *ELF64ProgramHeader) GetAlignment() uint64 {
	return h.Align
}

func (h *ELF32ProgramHeader) GetType() ProgramHeaderType {
	return h.Type
}

func (h *ELF32ProgramHeader) GetFlags() ProgramHeaderFlags {
	return h.Flags
}

func (h *ELF32ProgramHeader) GetFileOffset() uint64 {
	return uint64(h.FileOffset)
}

func (h *ELF32ProgramHeader) GetVirtualAddress() uint64 {
	return uint64(h.VirtualAddress)
}

func (h *ELF32ProgramHeader) GetPhysicalAddress() uint64 {
	return uint64(h.PhysicalAddress)
}

func (h *ELF32ProgramHeader) GetFileSize() uint64 {
	return uint64(h.FileSize)
}

func (h *ELF32ProgramHeader) GetMemorySize() uint64 {
	return uint64(h.MemorySize)
}

func (h *ELF32ProgramHeader) GetAlignment() uint64 {
	return uint64(h.Align)
}

// This is an interface used to access either 64- or 32-bit ELF symbol table
// entries.
type ELFSymbol interface {
	GetName() uint32
	GetInfo() ELFSymbolInfo
	GetOther() uint8
	GetSectionIndex() uint16
	GetValue() uint64
	GetSize() uint64
	String() string
}

func (s *ELF64Symbol) GetName() uint32 {
	return s.Name
}

func (s *ELF64Symbol) GetInfo() ELFSymbolInfo {
	return s.Info
}

func (s *ELF64Symbol) GetOther() uint8 {
	return s.Other
}

func (s *ELF64Symbol) GetSectionIndex() uint16 {
	return s.SectionIndex
}

func (s *ELF64Symbol) GetValue() uint64 {
	return s.Value
}

func (s *ELF64Symbol) GetSize() uint64 {
	return s.Size
}

func (s *ELF32Symbol) GetName() uint32 {
	return s.Name
}

func (s *ELF32Symbol) GetInfo() ELFSymbolInfo {
	return s.Info
}

func (s *ELF32Symbol) GetOther() uint8 {
	return s.Other
}

func (s *ELF32Symbol) GetSectionIndex() uint16 {
	return s.SectionIndex
}

func (s *ELF32Symbol) GetValue() uint64 {
	return uint64(s.Value)
}

func (s *ELF32Symbol) GetSize() uint64 {
	return uint64(s.Size)
}

// This holds a generic entry in a relocation table for either a 32- or 64-bit
// ELF file.
type ELFRelocation interface {
	Offset() uint64
	Type() uint32
	SymbolIndex() uint32
	Addend() int64
	String() string
}

type ELFDynamicTag interface {
	GetValue() int64
	String() string
}

func (t ELF64DynamicTag) GetValue() int64 {
	return int64(t)
}

func (t ELF32DynamicTag) GetValue() int64 {
	return int64(t)
}

type ELFDynamicEntry interface {
	GetTag() ELFDynamicTag
	GetValue() uint64
}

func (n *ELF64DynamicEntry) GetTag() ELFDynamicTag {
	return n.Tag
}

func (n *ELF32DynamicEntry) GetTag() ELFDynamicTag {
	return n.Tag
}

func (n *ELF64DynamicEntry) GetValue() uint64 {
	return n.Value
}

func (n *ELF32DynamicEntry) GetValue() uint64 {
	return uint64(n.Value)
}

// This function parses any ELF file and returns an instance of the ELFFile
// interface if no errors occur.
func ParseELFFile(raw []byte) (ELFFile, error) {
	if len(raw) < 5 {
		return nil, fmt.Errorf("Invalid ELF file: is only %d bytes", len(raw))
	}
	if raw[4] == 2 {
		return ParseELF64File(raw)
	}
	return ParseELF32File(raw)
}
