package openssl

import "C"

// #include <openssl/bn.h>
// #include <shim.h>
import "C"
import (
	"errors"
	"fmt"
	"runtime"
)

type Bignum struct {
	bn *C.BIGNUM
}

func newBignum() (*Bignum, error) {
	osslBn := C.BN_new()
	if osslBn == nil {
		return nil, errors.New("failed to create bignum")
	}
	bn := &Bignum{bn: osslBn}
	runtime.SetFinalizer(bn, func(b *Bignum) {
		if b.bn != nil {
			C.BN_free(b.bn)
			b.bn = nil
		}
	})
	return bn, nil
}
func newBignumFromInt(n int) (*Bignum, error) {
	bn, err := newBignum()
	if err != nil {
		return nil, err
	}
	if err := bn.SetValue(n); err != nil {
		return nil, err
	}
	return bn, nil
}

func (b *Bignum) SetValue(v int) error {
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting bignum value: %w", err)
	}
	if int(C.BN_set_word(b.bn, (C.BN_ULONG)(v))) != 1 {
		return fmt.Errorf("failed setting bignum value: %w", errorFromErrorQueue())
	}
	return nil
}

func (b *Bignum) NumBytes() int {
	return int(C.X_BN_num_bytes(b.bn))
}

func (b *Bignum) GetValue() int {
	return int(C.BN_get_word(b.bn))
}
