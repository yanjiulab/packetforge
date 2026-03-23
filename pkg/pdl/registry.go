package pdl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Registry protocol registry: protocol name -> definition; struct name -> definition
type Registry struct {
	protocols map[string]*Protocol
	structs   map[string]*Struct
}

func NewRegistry() *Registry {
	return &Registry{
		protocols: make(map[string]*Protocol),
		structs:    make(map[string]*Struct),
	}
}

// Register registers a protocol
func (r *Registry) Register(proto *Protocol) {
	r.protocols[strings.ToLower(proto.Name)] = proto
}

// RegisterStruct registers a struct (repeated structure definition)
func (r *Registry) RegisterStruct(st *Struct) {
	r.structs[strings.ToLower(st.Name)] = st
}

// GetStruct gets a struct definition by name
func (r *Registry) GetStruct(name string) *Struct {
	return r.structs[strings.ToLower(name)]
}

// LoadPDLFile loads and parses a single PDL file, registering all protocols and structs to the Registry
func (r *Registry) LoadPDLFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return r.LoadPDLContent(path, string(data))
}

// LoadPDLContent parses PDL source and registers all protocols and structs.
func (r *Registry) LoadPDLContent(sourceName, content string) error {
	parser := NewParser(content)
	protos, structs, err := parser.ParseFile()
	if err != nil {
		return fmt.Errorf("parse %s: %w", sourceName, err)
	}
	for _, st := range structs {
		r.RegisterStruct(st)
	}
	for _, p := range protos {
		r.Register(p)
	}
	return nil
}

// LoadPDLDir loads all .pdl files in the directory
func (r *Registry) LoadPDLDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".pdl" {
			continue
		}
		if err := r.LoadPDLFile(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// Get gets a protocol by name (lowercase match)
func (r *Registry) Get(name string) *Protocol {
	return r.protocols[strings.ToLower(name)]
}

// List returns a list of registered protocol names
func (r *Registry) List() []string {
	var names []string
	for n := range r.protocols {
		names = append(names, n)
	}
	return names
}
