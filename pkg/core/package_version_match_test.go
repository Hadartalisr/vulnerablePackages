package core

import (
	"fmt"
	"testing"
)

func TestIsMatch(t *testing.T) {

	var tests = []struct {
		version, versionRange string
		want                  bool
	}{
		{"4", ">= 4.0.0, < 4.5.0", true},
		{"4.0", ">= 4.0.0, < 4.5.0", true},
		{"4.0.0", ">= 4.0.0, < 4.5.0", true},
		{"4.3.0", ">= 4.0.0, < 4.5.0", true},
		{"4.0.1", ">= 4.0.0, < 4.5.0", true},
		{"4.4.5", ">= 4.0.0, < 4.5.0", true},
		{"3", ">= 4.0.0, < 4.5.0", false},
		{"3.4.0", ">= 4.0.0, < 4.5.0", false},
		{"3.9.9", ">= 4.0.0, < 4.5.0", false},
		{"4.9.9", ">= 4.0.0, < 4.5.0", false},
		{"5.0.0", ">= 4.0.0, < 4.5.0", false},
		{"4.5.0", ">= 4.0.0, < 4.5.0", false},
		{"4.5.0", "< 4.5.0, >= 4.0.0", false},

		{"4.5.0", "< 3.11.0", false},
		{"3.11", "< 3.11.0", false},
		{"3.11.0", "< 3.11.0", false},
		{"3.11.1", "< 3.11.0", false},
		{"3.10.1", "< 3.11.0", true},
		{"2.20.1", "< 3.11.0", true},

		{"0.2", "= 0.2.0", true},
		{"0.2.0", "= 0.2.0", true},
		{"0.4.0", "= 0.2.0", false},
		{"1.4.0", "= 0.2.0", false},

		{"1.4.0", "= 0.2.0, = 0.2.0", false},
		{"0.2.0", "= 0.2.0, <= 0.2.0", true},
		{"0.2.0", "= 0.2.0, < 0.2.0", false},
		{"0.2.0", "= 0.2.0, = 0.2.0", true},
	}

	for _, test := range tests {
		testName := fmt.Sprintf("%s ||| %s", test.versionRange, test.version)
		t.Run(testName, func(t *testing.T) {
			match, err := isMatch(test.versionRange, test.version)
			if err != nil {
				t.Error("error should not occur", err)
			}
			if match != test.want {
				t.Errorf("got %v, want %v", match, test.want)
			}
		})
	}

}
