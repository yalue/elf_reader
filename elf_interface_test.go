package elf_reader

import (
	"testing"
)

func TestELFInterface(t *testing.T) {
	testFile := func(filename string, expectedSectionCount uint16) {
		contents := fileBytes(filename, t)
		f, e := ParseELFFile(contents)
		if e != nil {
			t.Errorf("Failed parsing %s: %s\n", filename, e)
			return
		}
		if f.GetSectionCount() != expectedSectionCount {
			t.Errorf("Expected %d sections in %s, got %d\n",
				expectedSectionCount, filename, f.GetSectionCount())
			return
		}
	}
	testFile("test_data/sleep_arm32", 30)
	testFile("test_data/sleep_amd64", 29)
}

func TestGetBssContents(t *testing.T) {
	testFile := func(filename string) {
		contents := fileBytes(filename, t)
		f, e := ParseELFFile(contents)
		if e != nil {
			t.Errorf("Error loading %s: %s\n", filename, e)
			return
		}
		bssIdx := uint16(0xffff)
		for i := uint16(1); i < f.GetSectionCount(); i++ {
			name, e := f.GetSectionName(i)
			if e != nil {
				t.Errorf("Error getting name of section %d in %s: %s\n", i,
					filename, e)
				return
			}
			if name == ".bss" {
				bssIdx = i
				break
			}
		}
		if bssIdx == 0xffff {
			t.Errorf("Couldn't find index of .bss section in %s", filename)
			return
		}
		_, e = f.GetSectionContent(bssIdx)
		if e == nil {
			t.Errorf("Didn't get expected error when reading content of " +
				".bss section\n")
			return
		}
		t.Logf("Got expected error when reading .bss section content: %s\n", e)
	}
	testFile("test_data/bash32_freebsd")
	testFile("test_data/sleep_amd64")
	testFile("test_data/sleep_arm32")
	testFile("test_data/ld-linux_arm32.so")
}
