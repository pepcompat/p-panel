package facts

import (
	"strings"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	in := "# c\nID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME='Ubuntu 24.04 LTS'\nbad line\n"
	kv := ParseOSRelease(strings.NewReader(in))
	if kv["ID"] != "ubuntu" || kv["VERSION_ID"] != "24.04" || kv["PRETTY_NAME"] != "Ubuntu 24.04 LTS" {
		t.Fatalf("got %#v", kv)
	}
}

func TestCollectNoPanic(t *testing.T) {
	o := Collect()
	if o.Arch == "" || o.ID == "" {
		t.Fatalf("empty facts %#v", o)
	}
}
