package goencrypt

import "testing"

type testPair struct {
	in  interface{}
	out string
}

var pairs = []testPair{
	{"hello world", "5eb63bbbe01eeed093cb22bb8f5acdc3"},
	{123456789, ""},
	{[]byte("hello world"), "5eb63bbbe01eeed093cb22bb8f5acdc3"},
}

func TestMD5(t *testing.T) {
	for _, p := range pairs {
		out, _ := MD5(p.in)
		if string(out) != p.out {
			t.Errorf("bad return value: got: %s want: %s", string(out), p.out)
		}
	}
}

func BenchmarkMD5(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if i%3 == 0 {
			out, _ := MD5(pairs[0].in)
			if string(out) != pairs[0].out {
				b.Errorf("bad return value: got: %s want: %s", string(out), pairs[0].out)
			}
		} else if i%3 == 1 {
			out, _ := MD5(pairs[1].in)
			if string(out) != pairs[1].out {
				b.Errorf("bad return value: got: %s want: %s", string(out), pairs[1].out)
			}
		} else {
			out, _ := MD5(pairs[2].in)
			if string(out) != pairs[2].out {
				b.Errorf("bad return value: got: %s want: %s", string(out), pairs[2].out)
			}
		}
	}
}
