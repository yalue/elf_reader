// The elf_view executable is yet-another-ELF-viewer program joining the likes
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
	var sectionIndex uint16
	var e error
	for i := range f.Sections {
		if !f.IsDynamicSection(uint16(i)) {
			continue
		}
		sectionIndex = uint16(i)
		break
	}
	if sectionIndex == 0 {
		log.Printf("No dynamic linking table was found.\n")
		return nil
	}
	name, e := f.GetSectionName(sectionIndex)
	if e != nil {
		return fmt.Errorf("Failed getting dynamic table section name: %s",
			e)
	}
	entries, e := f.GetDynamicTable(sectionIndex)
	if e != nil {
		return fmt.Errorf("Failed parsing the dynamic section: %s", e)
	}
	log.Printf("Dynamic linking table in section %s:\n", name)
	stringContent, e := f.GetSectionContent(
		uint16(f.Sections[sectionIndex].LinkedIndex))
	if e != nil {
		return fmt.Errorf("Failed getting strings for dynamic section: %s", e)
	}
	var stringValue []byte
	for i := range entries {
		entry := &(entries[i])
		// If the tag indicates a string value, we'll print the string instead
		// of the default format.
		switch entry.Tag {
		case 1, 14, 15:
			stringValue, e = elf_reader.ReadStringAtOffset(entry.Value,
				stringContent)
			if e != nil {
				return fmt.Errorf("Failed getting string value for tag %s: %s",
					entry.Tag, e)
			}
			log.Printf("  %d. %s: %s\n", i, entry.Tag, stringValue)
		default:
			log.Printf("  %d. %s\n", i, entry)
		}
		if entry.Tag == 0 {
			break
		}
	}
	return nil
}

func printGNUVersionRequirements(f *elf_reader.ELF32File) error {
	var sectionIndex uint16
	// The file should only have one of these sections.
	for i := range f.Sections {
		if !f.IsVersionRequirementSection(uint16(i)) {
			continue
		}
		sectionIndex = uint16(i)
		break
	}
	if sectionIndex == 0 {
		log.Printf("No GNU version requirement section was found.")
		return nil
	}
	section := &(f.Sections[sectionIndex])
	stringContent, e := f.GetSectionContent(uint16(section.LinkedIndex))
	if e != nil {
		return fmt.Errorf("Couldn't get string table for GNU version "+
			"requirement section: %s", e)
	}
	need, aux, e := f.ParseVersionRequirementSection(sectionIndex)
	if e != nil {
		return fmt.Errorf("Failed parsing GNU version req. section: %s", e)
	}
	sectionName, e := f.GetSectionName(uint16(sectionIndex))
	if e != nil {
		return fmt.Errorf("Failed getting GBU version req. section name: %s",
			e)
	}
	log.Printf("GNU version requirements in section %s:\n", sectionName)
	var fileName, requirementName []byte
	for i, n := range need {
		fileName, e = elf_reader.ReadStringAtOffset(n.File, stringContent)
		if e != nil {
			return fmt.Errorf("Failed reading required file name: %s", e)
		}
		log.Printf(" File %d: %s, version %d\n", i, fileName, n.Version)
		for j, x := range aux[i] {
			requirementName, e = elf_reader.ReadStringAtOffset(x.Name,
				stringContent)
			if e != nil {
				return fmt.Errorf("Failed reading requirement name: %s", e)
			}
			log.Printf("   Requirement %d: %s, hash 0x%08x\n", j,
				requirementName, x.Hash)
		}
	}
	return nil
}

func run() int {
	var inputFile string
	var showSections, showSegments, showSymbols, showStrings,
		showRelocations, showDynamic, showRequirements bool
	var dumpSection int
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
	flag.BoolVar(&showRequirements, "requirements", false,
		"Prints a list of the GNU version requirements if set.")
	flag.IntVar(&dumpSection, "dump_section", -1,
		"If a valid section index is provided, binary contents of the section"+
			" will be dumped to stdout and other output will be surpressed.")
	flag.Parse()
	if inputFile == "" {
		log.Println("Invalid arguments. Run with -help for more information.")
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
	if dumpSection != -1 {
		content, e := elf.GetSectionContent(uint16(dumpSection))
		if e != nil {
			log.Printf("Failed dumping section contents: %s\n", e)
			return 1
		}
		log.Printf("%s", content)
		return 0
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
	if showRequirements {
		log.Println("==== GNU version requirements ====")
		e = printGNUVersionRequirements(elf)
		if e != nil {
			log.Printf("Error printing GNU version requirements: %s\n", e)
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
