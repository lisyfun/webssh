//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/tc-hib/winres"
)

func main() {
	f, err := os.Open("frontend/favicon.ico")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	icon, err := winres.LoadICO(f)
	if err != nil {
		panic(err)
	}

	rs := &winres.ResourceSet{}
	rs.SetIcon(winres.ID(3), icon)

	for _, arch := range []winres.Arch{winres.ArchAMD64, winres.ArchI386} {
		fname := fmt.Sprintf("rsrc_windows_%s.syso", arch)
		f, err := os.Create(fname)
		if err != nil {
			panic(err)
		}
		if err := rs.WriteObject(f, arch); err != nil {
			f.Close()
			os.Remove(fname)
			panic(err)
		}
		f.Close()
		fmt.Println("generated", fname)
	}
}
