package yara

import (
	"io/ioutil"
	"os"
	"testing"
)

func makeRules(t *testing.T, rule string) *Rules {
	c, err := NewCompiler()
	if c == nil || err != nil {
		t.Fatal("NewCompiler():", err)
	}
	if err = c.AddString(rule, ""); err != nil {
		t.Fatal("AddString():", err)
	}
	r, err := c.GetRules()
	if err != nil {
		t.Fatal("GetRules:", err)
	}
	return r
}

func TestSimpleMatch(t *testing.T) {
	r := makeRules(t,
		"rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }")
	m, err := r.ScanMem([]byte(" abc "), 0, 0)
	if err != nil {
		t.Errorf("ScanMem: %s", err)
	}
	t.Logf("Matches: %+v", m)
}

func TestSimpleFileMatch(t *testing.T) {
	r, _ := Compile(
		"rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }",
		nil)
	tf, _ := ioutil.TempFile("", "TestSimpleFileMatch")
	defer os.Remove(tf.Name())
	tf.Write([]byte(" abc "))
	tf.Close()
	m, err := r.ScanFile(tf.Name(), 0, 0)
	if err != nil {
		t.Errorf("ScanFile(%s): %s", tf.Name(), err)
	}
	t.Logf("Matches: %+v", m)
}

func TestEmpty(t *testing.T) {
	r, _ := Compile("rule test { condition: true }", nil)
	r.ScanMem([]byte{}, 0, 0)
	t.Log("Scan of null-byte slice did not crash. Yay.")
}

func assertTrueRules(t *testing.T, rules []string, data []byte) {
	for _, rule := range rules {
		r := makeRules(t, rule)
		if m, err := r.ScanMem(data, 0, 0); len(m) == 0 {
			t.Errorf("Rule < %s > did not match data < %v >", rule, data)
		} else if err != nil {
			t.Errorf("Error %s", err)
		}
	}
}

func assertFalseRules(t *testing.T, rules []string, data []byte) {
	for _, rule := range rules {
		r := makeRules(t, rule)
		if m, err := r.ScanMem(data, 0, 0); len(m) > 0 {
			t.Errorf("Rule < %s > matched data < %v >", rule, data)
		} else if err != nil {
			t.Errorf("Error %s", err)
		}
	}
}

func TestLoad(t *testing.T) {
	r, err := LoadRules("testrules.yac")
	if r == nil || err != nil {
		t.Fatalf("LoadRules: %s", err)
	}
}
