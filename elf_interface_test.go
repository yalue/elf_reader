package elf_reader

import (
	"testing"
)

func TestELFInterface(t *testing.T) {
	testFile := fileBytes("test_data/sleep_arm32", t)
	f, e := ParseELFFile(testFile)
	if e != nil {
		t.Logf("Failed parsing a 32-bit ELF file: %s\n", e)
		t.FailNow()
	}
	sectionCount, e := f.GetSectionCount()
	if e != nil {
		t.Logf("Failed getting section count in the 32-bit ELF file: %s\n", e)
		t.FailNow()
	}
	if sectionCount != 30 {
		t.Logf("Expected 30 sections in the 32-bit ELF file, got %d\n",
			sectionCount)
		t.Fail()
	}
	testFile = fileBytes("test_data/sleep_amd64", t)
	f, e = ParseELFFile(testFile)
	if e != nil {
		t.Logf("Failed parsing a 64-bit ELF file: %s\n", e)
		t.FailNow()
	}
	sectionCount, e = f.GetSectionCount()
	if e != nil {
		t.Logf("Failed getting section count in the 64-bit ELF file: %s\n", e)
		t.FailNow()
	}
	if sectionCount != 29 {
		t.Logf("Expected 29 sections in the 64-bit ELF file, got %d\n",
			sectionCount)
		t.Fail()
	}
}
