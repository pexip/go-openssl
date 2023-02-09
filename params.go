package openssl

// #include <openssl/param_build.h>
import "C"
import (
	"runtime"
	"unsafe"
)

type ParamPair struct {
	key   *C.char
	value unsafe.Pointer
}
type ParamBld struct {
	bld    *C.OSSL_PARAM_BLD
	params []*ParamPair
}
type Param struct {
	param *C.OSSL_PARAM
}

func newParamPair(key *C.char, value unsafe.Pointer) *ParamPair {
	pair := &ParamPair{key, value}
	runtime.SetFinalizer(pair, func(p *ParamPair) {
		C.free(unsafe.Pointer(p.key))
		if p.value != nil {
			C.free(p.value)
		}
	})
	return pair
}

func NewParamBld() (*ParamBld, error) {
	bld := C.OSSL_PARAM_BLD_new()
	if bld == nil {
		return nil, errorFromErrorQueue()
	}
	paramBld := &ParamBld{bld, make([]*ParamPair, 0, 1)}
	runtime.SetFinalizer(paramBld, func(p *ParamBld) {
		if p.bld != nil {
			C.OSSL_PARAM_BLD_free(p.bld)
			p.bld = nil
		}
	})
	return paramBld, nil
}

func (p *ParamBld) PushString(key string, value string) error {
	ckey := C.CString(key)
	cvalue := C.CString(value)
	param := newParamPair(ckey, unsafe.Pointer(cvalue))

	if int(C.OSSL_PARAM_BLD_push_utf8_string(p.bld, ckey, cvalue, 0)) != 1 {
		return errorFromErrorQueue()
	}
	p.params = append(p.params, param)
	return nil
}

func (p *ParamBld) PushOctetString(key string, value []byte) error {
	ckey := C.CString(key)
	param := newParamPair(ckey, nil)

	if int(C.OSSL_PARAM_BLD_push_octet_string(
		p.bld, ckey, unsafe.Pointer(&value[0]), C.size_t(len(value)),
	)) != 1 {
		return errorFromErrorQueue()
	}
	p.params = append(p.params, param)
	return nil
}

func (p *ParamBld) PushUInt(key string, value uint) error {
	ckey := C.CString(key)
	param := newParamPair(ckey, nil)

	if int(C.OSSL_PARAM_BLD_push_uint(p.bld, ckey, C.uint(value))) != 1 {
		return errorFromErrorQueue()
	}
	p.params = append(p.params, param)
	return nil
}

// ToParam convert this ParamBld to Param
func (p *ParamBld) ToParam() (*Param, error) {
	prm := C.OSSL_PARAM_BLD_to_param(p.bld)
	if prm == nil {
		return nil, errorFromErrorQueue()
	}
	param := &Param{prm}
	runtime.SetFinalizer(param, func(p *Param) { p.free() })
	return param, nil
}

func (p *Param) free() {
	if p.param != nil {
		C.OSSL_PARAM_free(p.param)
		p.param = nil
	}
}
