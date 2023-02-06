package openssl

import (
	"fmt"
	"testing"
)

var TestNumbers = []int{1, 16, 100, 255, 1023, 65536, 16777216, 4127195136}

func TestIntToBigNum(t *testing.T) {
	for _, i := range TestNumbers {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			bn, err := newBignumFromInt(i)
			if err != nil {
				t.Fatal(err)
			}
			j := bn.GetValue()
			if i != j {
				t.Fatalf(fmt.Sprintf("%d != %d", i, j))
			}
		})
	}
}
