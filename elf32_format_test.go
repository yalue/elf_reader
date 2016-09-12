package elf_reader

import (
	"io/ioutil"
	"os"
	"testing"
)

// Returns the content of the file with the given name.
func fileBytes(filename string, t *testing.T) []byte {
	f, e := os.Open(filename)
	if e != nil {
		t.Logf("Failed opening file: %s\n", e)
		t.FailNow()
	}
	toReturn, e := ioutil.ReadAll(f)
	f.Close()
	if e != nil {
		t.Logf("Failed reading file: %s\n", e)
		t.FailNow()
	}
	return toReturn
}

func TestParseELF32File(t *testing.T) {
	testFile := fileBytes("test_data/sleep_arm32", t)
	f, e := ParseELF32File(testFile)
	if e != nil {
		t.Logf("Error parsing file: %s\n", e)
		t.FailNow()
	}
	var name string
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
	// Test reading the .dynsym section
	found := false
	for i := range f.Sections {
		if !f.IsSymbolTable(uint16(i)) {
			continue
		}
		name, e = f.GetSectionName(uint16(i))
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
