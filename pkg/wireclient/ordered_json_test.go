package wireclient

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestOrderedJSONEscapeSolidusAndKeyOrder(t *testing.T) {
	raw := []byte(`{"z_url":"https:\/\/api.example.com\/v1","a_num":3.0,"b_int":3,"html":"a<b>&c"}`)
	style := DetectJSONStyle(raw)
	if !style.EscapeSolidus {
		t.Fatalf("expected EscapeSolidus=true")
	}
	val, err := UnmarshalOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	om := val.(*OrderedMap)
	if len(om.Pairs) != 4 || om.Pairs[0].Key != "z_url" || om.Pairs[1].Key != "a_num" {
		t.Fatalf("key order lost: %+v", om.Pairs)
	}
	if om.Pairs[1].Value.(json.Number).String() != "3.0" || om.Pairs[2].Value.(json.Number).String() != "3" {
		t.Fatalf("number formatting lost: %+v", om.Pairs)
	}

	out, err := MarshalOrdered(om, JSONMarshalOptions{EscapeSolidus: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Fatalf("roundtrip mismatch:\nwant: %s\ngot:  %s", raw, out)
	}

	// Verify body MD5 differs if EscapeSolidus is turned off
	outNoSlash, _ := MarshalOrdered(om, JSONMarshalOptions{EscapeSolidus: false})
	sum1 := md5.Sum(out)
	sum2 := md5.Sum(outNoSlash)
	if strings.ToUpper(hex.EncodeToString(sum1[:])) == strings.ToUpper(hex.EncodeToString(sum2[:])) {
		t.Fatalf("expected body MD5 digest to differ with EscapeSolidus false")
	}
}
