package jobs

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParamsShape: CheckParamsShape/DecodeStrict never panic; whatever
// passes is one JSON object within the size/depth/node bounds and NUL-free.
func FuzzParamsShape(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":[1,2,{"b":"\u0000"}]}`, `[]`, `{"a":1}{"b":2}`, `{"a":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`,
		`{"\u0000":1}`, `{"a":"\\u0000"}`, ` {"a":1} `, `{"a":1e999}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		err := CheckParamsShape(raw)
		var dst struct {
			A any `json:"a"`
		}
		strictErr := DecodeStrict(raw, &dst)
		if err != nil {
			return
		}
		if len(raw) > MaxParamsBytes || !json.Valid(raw) {
			t.Fatalf("invalid params accepted: %q", raw)
		}
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&v) != nil {
			t.Fatal("not decodable")
		}
		if _, ok := v.(map[string]any); !ok {
			t.Fatalf("non-object accepted: %q", raw)
		}
		var walk func(any, int)
		walk = func(x any, d int) {
			if d > MaxParamsDepth {
				t.Fatalf("too deep accepted")
			}
			switch y := x.(type) {
			case string:
				if strings.IndexByte(y, 0) >= 0 {
					t.Fatal("NUL accepted")
				}
			case map[string]any:
				for k, z := range y {
					if strings.IndexByte(k, 0) >= 0 {
						t.Fatal("NUL key accepted")
					}
					walk(z, d+1)
				}
			case []any:
				for _, z := range y {
					walk(z, d+1)
				}
			}
		}
		walk(v, 1)
		_ = strictErr
	})
}
