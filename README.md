ELF Reader
==========

About
-----

This library is for reading ELF files using the Go programming language. Go's
standard library already includes ELF-related functions, but these do not
include some useful functionality for displaying or accessing some aspects of
ELF files out-of-the-box.

This library supports both big and little-endian 32-bit ELF files for now. In
the future, 64-bit support will probably be added.

Usage
-----

The following example shows how this library can be used to output section
names to standard output. For a more complete example of how to read
information from an ELF file, see the command-line tool at
`elf_view/elf_view.go`.

```go
import (
	"fmt"
	"github.com/yalue/elf_reader"
	"io/ioutil"
)

func main() {
	// Print the section names in /bin/bash
	raw, e := ioutil.ReadFile("/bin/bash")
	if e != nil {
		fmt.Printf("Failed reading /bin/bash: %s\n", e)
		return
	}
	elf, e := elf_reader.ParseELF32File(raw)
	if e != nil {
		fmt.Printf("Failed parsing ELF file: %s\n", e)
		return
	}
	for i := range elf.Sections {
		if i == 0 {
			fmt.Printf("Section 0: NULL section (no name)\n")
			continue
		}
		name, e := elf.GetSectionName(uint16(i))
		if e != nil {
			fmt.Printf("Failed getting section %d name: %s\n", i, e)
			continue
		}
		fmt.Printf("Section %d name: %s\n", i, name)
	}
}
```
