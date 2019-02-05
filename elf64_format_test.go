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
