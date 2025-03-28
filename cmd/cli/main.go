package main

import (
	"fmt"

	"github.com/linkdata/minidns"
	"github.com/miekg/dns"
)

func main() {
	r, err := minidns.NewResolver("192.36.148.17:53", true)
	if err == nil {
		var msg *dns.Msg
		msg, err = r.Lookup("console.aws.amazon.com", dns.TypeA)
		// msg, err = r.Lookup("seb.org.tw", dns.TypeA)
		if err == nil {
			fmt.Println(msg)
		}
	}
	if err != nil {
		fmt.Println(err.Error())
	}
}
