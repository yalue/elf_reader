// The elf_view executable is yet-another-ELF-viewer program joinging the likes
// of objdump and readelf, but is probably less complete. It exists primarily
// to facilitate testing of the elf_reader package.
//
// Example usage: ./elf_view -file <elf_file> -show_sections
package main

import (
	"flag"
	"fmt"
	"github.com/yalue/elf_reader"
	"io/ioutil"
	"log"
	"os"
)

func printSections(f *elf_reader.ELF32File) error {
	var name string
	var e error
	for i := range f.Sections {
		if i != 0 {
			name, e = f.GetSectionName(uint16(i))
		} else {
			name, e = "<null section>", nil
		}
		if e != nil {
			return fmt.Errorf("Error getting section %d name: %s", i, e)
		}
		log.Printf("%d. %s: %s\n", i, name, &(f.Sections[i]))
	}
	return nil
}

func printSegments(f *elf_reader.ELF32File) error {
	for i := range f.Segments {
		log.Printf("%d. %s\n", i, &(f.Segments[i]))
	}
	return nil
}

func printSymbols(f *elf_reader.ELF32File) error {
	for i := range f.Sections {
		if !f.IsSymbolTable(uint16(i)) {
			continue
		}
		name, e := f.GetSectionName(uint16(i))
		if e != nil {
			return fmt.Errorf("Error getting symbol table name: %s", e)
		}
		symbols, names, e := f.GetSymbolTable(uint16(i))
		if e != nil {
			return fmt.Errorf("Couldn't read symbol table: %s", e)
		}
		log.Printf("%d symbols in section %s:\n", len(symbols), name)
		for j := range symbols {
			log.Printf("  %d. %s: %s\n", j, names[j], &(symbols[j]))
		}
	}
	return nil
}

func printStrings(f *elf_reader.ELF32File) error {
	for i := range f.Sections {
		if !f.IsStringTable(uint16(i)) {
			continue
		}
		name, e := f.GetSectionName(uint16(i))
		if e != nil {
			return fmt.Errorf("Error getting string table name: %s", e)
		}
		splitStrings, e := f.GetStringTable(uint16(i))
		if e != nil {
			return fmt.Errorf("Couldn't read string table: %s", e)
		}
		log.Printf("%d strings in section %s:\n", len(splitStrings), name)
		for j, s := range splitStrings {
			log.Printf("  %d. %s\n", j, s)
		}
	}
	return nil
}

func printRelocations(f *elf_reader.ELF32File) error {
	for i := range f.Sections {
		if !f.IsRelocationTable(uint16(i)) {
			continue
		}
		name, e := f.GetSectionName(uint16(i))
		if e != nil {
			return fmt.Errorf("Error getting relocation table name: %s", e)
		}
		relocations, e := f.GetRelocationTable(uint16(i))
		if e != nil {
			return fmt.Errorf("Couldn't read relocation table: %s", e)
		}
		log.Printf("%d relocations in section %s:\n", len(relocations), name)
		for j, r := range relocations {
			log.Printf("  %d. %s\n", j, r)
		}
	}
	return nil
}

func printDynamicLinkingTable(f *elf_reader.ELF32File) error {
	for i := range f.Sections {
		if !f.IsDynamicSection(uint16(i)) {
			continue
		}
		name, e := f.GetSectionName(uint16(i))
		if e != nil {
			return fmt.Errorf("Failed getting dynamic table section name: %s",
				e)
		}
		entries, e := f.GetDynamicTable(uint16(i))
		if e != nil {
			return fmt.Errorf("Failed parsing the dynamic section: %s\n", e)
		}
		log.Printf("Dynamic linking table in section %s:\n", name)
		for j := range entries {
			entry := &(entries[j])
			log.Printf("  %d. %s\n", j, entry)
			if entry.Tag == 0 {
				break
			}
		}
	}
	return nil
}

func run() int {
	var inputFile string
	var showSections, showSegments, showSymbols, showStrings,
		showRelocations, showDynamic bool
	flag.StringVar(&inputFile, "file", "",
		"The path to the input ELF file. This is required.")
	flag.BoolVar(&showSections, "sections", false,
		"Print a list of sections in the ELF file if set.")
	flag.BoolVar(&showSegments, "segments", false,
		"Print a list of segments (program headers) if set.")
	flag.BoolVar(&showSymbols, "symbols", false,
		"Print a list of symbols if set.")
	flag.BoolVar(&showStrings, "strings", false,
		"Prints the contents of the string tables if set.")
	flag.BoolVar(&showRelocations, "relocations", false,
		"Prints a list of relocations if set.")
	flag.BoolVar(&showDynamic, "dynamic", false,
		"Prints a list of dynamic linking table entries if set.")
	flag.Parse()
	if inputFile == "" {
		log.Printf("Invalid arguments. Run with -help for more information.")
		return 1
	}
	rawInput, e := ioutil.ReadFile(inputFile)
	if e != nil {
		log.Printf("Failed reading input file: %s\n", e)
		return 1
	}
	elf, e := elf_reader.ParseELF32File(rawInput)
	if e != nil {
		log.Printf("Failed parsing the input file: %s\n", e)
		return 1
	}
	log.Printf("Successfully parsed file %s\n", inputFile)
	if showSections {
		log.Println("==== Sections ====")
		e = printSections(elf)
		if e != nil {
			log.Printf("Error printing sections: %s\n", e)
			return 1
		}
	}
	if showSegments {
		log.Println("==== Segments ====")
		e = printSegments(elf)
		if e != nil {
			log.Printf("Error printing segments: %s\n", e)
			return 1
		}
	}
	if showSymbols {
		log.Println("==== Symbols ====")
		e = printSymbols(elf)
		if e != nil {
			log.Printf("Error printing symbols: %s\n", e)
			return 1
		}
	}
	if showStrings {
		log.Println("==== Strings ====")
		e = printStrings(elf)
		if e != nil {
			log.Printf("Error printing strings: %s\n", e)
			return 1
		}
	}
	if showRelocations {
		log.Println("==== Relocations ====")
		e = printRelocations(elf)
		if e != nil {
			log.Printf("Error printing relocations: %s\n", e)
			return 1
		}
	}
	if showDynamic {
		log.Println("==== Dynamic linking table ====")
		e = printDynamicLinkingTable(elf)
		if e != nil {
			log.Printf("Error printing the dynamic linking table: %s\n", e)
			return 1
		}
	}
	return 0
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	os.Exit(run())
}
