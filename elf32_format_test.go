package elf_reader

import (
	"os"
	"testing"
)

// Returns the content of the file with the given name.
func fileBytes(filename string, t *testing.T) []byte {
	toReturn, e := os.ReadFile(filename)
	if e != nil {
		t.Logf("Failed reading file: %s\n", e)
		t.FailNow()
	}
	return toReturn
}

func parseTestELF32(filename string, t *testing.T) *ELF32File {
	testFile := fileBytes(filename, t)
	f, e := ParseELF32File(testFile)
	if e != nil {
		t.Logf("Error parsing file %s: %s\n", filename, e)
		t.FailNow()
	}
	return f
}

func TestParseELF32File(t *testing.T) {
	f := parseTestELF32("test_data/sleep_arm32", t)
	var name string
	var e error
	if len(f.Sections) != 30 {
		t.Logf("Expected 30 sections, got %d\n", len(f.Sections))
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

func TestParseSymbols32(t *testing.T) {
	f := parseTestELF32("test_data/sleep_arm32", t)
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
		if len(symbols) != 8 {
			t.Logf("Expected 8 dynsym entries, got %d\n", len(symbols))
			t.Fail()
		}
		for j := range symbols {
			t.Logf("Symbol %s (index %d): %s\n", names[j], j, &(symbols[j]))
		}
	}
	if !found {
		t.Logf("Couldn't find .dynsym section in test file.\n")
		t.Fail()
	}
}

func TestParseRelocations32(t *testing.T) {
	f := parseTestELF32("test_data/sleep_arm32", t)
	found := false
	for i := range f.Sections {
		// Look for the .rel.plt section
		if !f.IsRelocationTable(uint16(i)) {
			continue
		}
		name, e := f.GetSectionName(uint16(i))
		if e != nil {
			t.Logf("Failed getting relocation section name: %s\n", e)
			t.FailNow()
		}
		if name != ".rel.plt" {
			continue
		}
		found = true
		relocations, e := f.GetRelocationTable(uint16(i))
		if e != nil {
			t.Logf("Failed parsing relocation table: %s\n", e)
			t.FailNow()
		}
		if len(relocations) != 7 {
			t.Logf("Expected 7 relocations, got %d\n", len(relocations))
			t.Fail()
		}
		for j, r := range relocations {
			t.Logf("Relocation %d: %s\n", j, r)
		}
	}
	if !found {
		t.Logf("Couldn't find .rel.plt section in the test file.\n")
		t.Fail()
	}
}

func TestParseDynamicTable32(t *testing.T) {
	f := parseTestELF32("test_data/sleep_arm32", t)
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

func TestParseVersionRequirements32(t *testing.T) {
	f := parseTestELF32("test_data/sleep_arm32", t)
	found := false
	for i := range f.Sections {
		if !f.IsVersionRequirementSection(uint16(i)) {
			continue
		}
		found = true
		need, aux, e := f.ParseVersionRequirementSection(uint16(i))
		if e != nil {
			t.Logf("Failed parsing version requirement section: %s\n", e)
			t.FailNow()
		}
		for j, n := range need {
			t.Logf("File %d: %s\n", j, &n)
			for k, x := range aux[j] {
				t.Logf("  Requirement %d: %s\n", k, &x)
			}
		}
	}
	if !found {
		t.Logf("Couldn't find the GNU version requirement section in the " +
			"test file.\n")
		t.Fail()
	}
}

func TestParseVersionDefinitions32(t *testing.T) {
	f := parseTestELF32("test_data/ld-linux_arm32.so", t)
	found := false
	for i := range f.Sections {
		if !f.IsVersionDefinitionSection(uint16(i)) {
			continue
		}
		found = true
		def, aux, e := f.ParseVersionDefinitionSection(uint16(i))
		if e != nil {
			t.Logf("Failed parsing version definition section: %s\n", e)
			t.FailNow()
		}
		for j, d := range def {
			t.Logf("Definition %d: %s\n", j, &d)
			for k, x := range aux[j] {
				t.Logf("  Aux %d: %s\n", k, &x)
			}
		}
	}
	if !found {
		t.Logf("Couldn't find the GNU version definition section in the " +
			"test shared library file.\n")
		t.Fail()
	}
}
