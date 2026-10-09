// read-path probe over the go-alpm consumer (cgo). identical output
// against puck's libalpm.so.16 and the real one proves the C ABI.
package main

import (
	"fmt"
	"os"
	"sort"

	alpm "github.com/Jguer/go-alpm/v2"
)

func dump(label string, db alpm.IDB) {
	type row struct {
		name, line string
	}
	var rows []row
	db.PkgCache().ForEach(func(p alpm.IPackage) error {
		rows = append(rows, row{p.Name(), fmt.Sprintf("  %s %s|%s|%s|%d|%d",
			label, p.Name(), p.Version(), p.Description(), p.ISize(),
			p.Reason())})
		return nil
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	for _, r := range rows {
		fmt.Println(r.line)
	}
}

func main() {
	h, err := alpm.Initialize(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}
	root, _ := h.Root()
	dbpath, _ := h.DBPath()
	fmt.Println("root", root)
	fmt.Println("dbpath", dbpath)

	local, _ := h.LocalDB()
	fmt.Println("localdb", local.Name())
	dump("local", local)

	sync, _ := h.RegisterSyncDB("testrepo", 0)
	fmt.Println("syncdb", sync.Name())
	dump("sync", sync)

	for _, p := range [][2]string{{"1.0", "1.0"}, {"1.0", "2.0"},
		{"2.0-1", "2.0-2"}, {"1:1.0", "2.0"}} {
		fmt.Println("vercmp", p[0], p[1], alpm.VerCmp(p[0], p[1]))
	}

	// NOTE: h.Release() is intentionally not called. go-alpm + libalpm 16
	// double-free in alpm_release against the REAL library too (upstream
	// go-alpm issue, not puck). see PORTING.md C ABI findings.
	_ = h
}
