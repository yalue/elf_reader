package elf_reader

import (
	"encoding/binary"
	"testing"
)

func TestReadStringAtOffset(t *testing.T) {
	buffer := []byte("\x00Hi there!\x00ASDFASDF")
	s, e := ReadStringAtOffset(0, buffer)
	if e != nil {
		t.Logf("Failed reading empty string: %s\n", e)
		t.FailNow()
	}
	if string(s) != "" {
		t.Logf("Read wrong string, expected \"\", got \"%s\"\n", string(s))
		t.FailNow()
	}
	s, e = ReadStringAtOffset(999, buffer)
	if e == nil {
		t.Logf("Didn't get expected error for reading invalid offset.\n")
		t.FailNow()
	}
	t.Logf("Got expected error for reading invalid offset: %s\n", e)
	s, e = ReadStringAtOffset(15, buffer)
	if e == nil {
		t.Logf("Didn't get expected error for reading unterminated string.\n")
		t.FailNow()
	}
	t.Logf("Got expected error for reading unterminated string: %s\n", e)
	s, e = ReadStringAtOffset(1, buffer)
	if e != nil {
		t.Logf("Failed reading valid string: %s\n", e)
		t.FailNow()
	}
	if string(s) != "Hi there!" {
		t.Logf("Read incorrect valid string: \"%s\"\n", string(s))
		t.FailNow()
	}
}

func TestELF32Hash(t *testing.T) {
	data := []byte{}
	hash := ELF32Hash(data)
	if hash != 0 {
		t.Logf("Got hash of 0x%08x for no data (expected 0).\n", hash)
		t.Fail()
	}
	data = []byte("Hi there lol")
	hash = ELF32Hash(data)
	if hash != 0x086c29bc {
		t.Logf("Got incorrect PJW hash: 0x%08x\n", hash)
		t.Fail()
	}
}

func TestWriteAtOffset(t *testing.T) {
	data := []byte("Hi there")
	toWrite := uint32(0x20212121)
	data, e := WriteAtOffset(data, uint64(len(data)), binary.BigEndian,
		toWrite)
	if e != nil {
		t.Logf("Failed writing data at offset: %s\n", e)
		t.FailNow()
	}
	if string(data) != "Hi there !!!" {
		t.Logf("Got wrong data after writing: %s\n", data)
		t.FailNow()
	}
}
