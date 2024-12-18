// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadHellomap returns the embedded CollectionSpec for hellomap.
func loadHellomap() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_HellomapBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load hellomap: %w", err)
	}

	return spec, err
}

// loadHellomapObjects loads hellomap and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*hellomapObjects
//	*hellomapPrograms
//	*hellomapMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadHellomapObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadHellomap()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// hellomapSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hellomapSpecs struct {
	hellomapProgramSpecs
	hellomapMapSpecs
}

// hellomapSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hellomapProgramSpecs struct {
	Hello *ebpf.ProgramSpec `ebpf:"hello"`
}

// hellomapMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hellomapMapSpecs struct {
	CounterTable *ebpf.MapSpec `ebpf:"counter_table"`
}

// hellomapObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadHellomapObjects or ebpf.CollectionSpec.LoadAndAssign.
type hellomapObjects struct {
	hellomapPrograms
	hellomapMaps
}

func (o *hellomapObjects) Close() error {
	return _HellomapClose(
		&o.hellomapPrograms,
		&o.hellomapMaps,
	)
}

// hellomapMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadHellomapObjects or ebpf.CollectionSpec.LoadAndAssign.
type hellomapMaps struct {
	CounterTable *ebpf.Map `ebpf:"counter_table"`
}

func (m *hellomapMaps) Close() error {
	return _HellomapClose(
		m.CounterTable,
	)
}

// hellomapPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadHellomapObjects or ebpf.CollectionSpec.LoadAndAssign.
type hellomapPrograms struct {
	Hello *ebpf.Program `ebpf:"hello"`
}

func (p *hellomapPrograms) Close() error {
	return _HellomapClose(
		p.Hello,
	)
}

func _HellomapClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed hellomap_bpfeb.o
var _HellomapBytes []byte
