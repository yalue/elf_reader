package elf_reader

import (
	"testing"
)

func parseTestELF64(filename string, t *testing.T) *ELF64File {
	testFile := fileBytes(filename, t)
	f, e := ParseELF64File(testFile)
	if e != nil {
		t.Logf("Error parsing ELF64 file %s: %s\n", filename, e)
		t.FailNow()
	}
	return f
}

func TestParseELF64File(t *testing.T) {
	f := parseTestELF64("test_data/sleep_amd64", t)
	var name string
	var e error
	if len(f.Sections) != 29 {
		t.Logf("Expected 29 sections, got %d\n", len(f.Sections))
		t.Fail()
	}
	for i := range f.Sections {
		if i != 0 {
			name, e = f.GetSectionName(uint16(i))
		} else {
			name, e = "<null section>", nil
		}
		if e != nil {
			t.Logf("Error getting section %d name: %s\n", i, e)
			t.FailNow()
		}
		t.Logf("Section %s (index %d): %s\n", name, i, &(f.Sections[i]))
	}
	if len(f.Segments) != 9 {
		t.Logf("Expected 9 segments, got %d\n", len(f.Segments))
		t.Fail()
	}
	for i := range f.Segments {
		t.Logf("Segment %d: %s\n", i, &(f.Segments[i]))
	}
}

func TestParseSymbols64(t *testing.T) {
	f := parseTestELF64("test_data/sleep_amd64", t)
	// Test reading the .dynsym section
	found := false
	for i := range f.Sections {
		if !f.IsSymbolTable(uint16(i)) {
			continue
		}
		name, e := f.GetSectionName(uint16(i))
		if e != nil {
			t.Logf("Failed getting symbol table section name: %s\n", e)
			t.FailNow()
		}
		if name != ".dynsym" {
			continue
		}
		found = true
		symbols, names, e := f.GetSymbolTable(uint16(i))
		if e != nil {
			t.Logf("Failed parsing symbol table: %s\n", e)
			t.FailNow()
		}
		if len(symbols) != 7 {
			t.Logf("Expected 7 dynsym entries, got %d\n", len(symbols))
			t.Fail()
		}
		for j := range symbols {
			t.Logf("Symbol %s (index %d): %s\n", names[j], j, &(symbols[j]))
		}
	}
	if !found {
		t.Logf("Couldn't find .dynsym section in the test file.\n")
		t.Fail()
	}
}

func TestParseRelocations64(t *testing.T) {
	f := parseTestELF64("test_data/sleep_amd64", t)
	// Test reading the .rela.plt section
	found := false
	for i := range f.Sections {
		if !f.IsRelocationTable(uint16(i)) {
			continue
		}
		name, e := f.GetSectionName(uint16(i))
		if e != nil {
			t.Logf("Failed getting relocation section name: %s\n", e)
			t.FailNow()
		}
		if name != ".rela.plt" {
			continue
		}
		found = true
		relocations, e := f.GetRelocationTable(uint16(i))
		if e != nil {
			t.Logf("Failed parsing relocation table: %s\n", e)
			t.FailNow()
		}
		if len(relocations) != 1 {
			t.Logf("Expected 1 entry, got %d\n", len(relocations))
			t.Fail()
		}
		for j, r := range relocations {
			t.Logf("Relocation %d: %s\n", j, r)
		}
	}
	if !found {
		t.Logf("Couldn't find .rela.plt section in the test file.\n")
		t.Fail()
	}
}

func TestParseDynamicTable64(t *testing.T) {
	f := parseTestELF64("test_data/sleep_amd64", t)
	found := false
	for i := range f.Sections {
		if !f.IsDynamicSection(uint16(i)) {
			continue
		}
		entries, e := f.GetDynamicTable(uint16(i))
		if e != nil {
			t.Logf("Failed parsing the dynamic section: %s\n", e)
			t.FailNow()
		}
		found = true
		if entries[len(entries)-1].Tag != 0 {
			t.Logf("The last dynamic entry tag wasn't 0.\n")
			t.Fail()
		}
		for j := range entries {
			entry := &(entries[j])
			t.Logf("Dynamic linking table entry %d: %s\n", j, entry)
			if entry.Tag == 0 {
				break
			}
		}
		break
	}
	if !found {
		t.Logf("Couldn't find .dynamic section in the test file.\n")
		t.Fail()
	}
}
