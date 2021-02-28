package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
)

type output struct {
	Nftables []struct {
		Set struct {
			Name string
			Elem []struct {
				Elem struct {
					Val     string
					Counter struct {
						Packets uint64
						Bytes   uint64
					}
				}
			}
		}
	}
}

func main() {
	do := func(w io.Writer, dir string) error {
		cmd := exec.Command("nft", "--json", "list", "set", "inet", "filter", "traffic_"+dir)
		out, err := cmd.Output()
		if err != nil {
			return err
		}
		var data output
		if err := json.Unmarshal(out, &data); err != nil {
			return err
		}
		for _, x := range data.Nftables {
			if x.Set.Name != "traffic_"+dir {
				continue
			}

			fmt.Fprintln(w, "# TYPE traffic_stats_"+dir+"_bytes_total counter")
			for _, elem := range x.Set.Elem {
				fmt.Fprintf(w, "traffic_stats_"+dir+"_bytes_total{ip=%q} %d\n", elem.Elem.Val, elem.Elem.Counter.Bytes)
			}

			fmt.Fprintln(w, "# TYPE traffic_stats_"+dir+"_packets_total counter")
			for _, elem := range x.Set.Elem {
				fmt.Fprintf(w, "traffic_stats_"+dir+"_packets_total{ip=%q} %d\n", elem.Elem.Val, elem.Elem.Counter.Packets)
			}
		}
		return nil
	}

	http.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		buf := bytes.NewBuffer(nil)
		if err := do(buf, "in"); err != nil {
			log.Println(err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := do(buf, "out"); err != nil {
			log.Println(err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		io.Copy(w, buf)
	})
	http.ListenAndServe(":10000", nil)
}
