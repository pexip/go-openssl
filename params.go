package openssl

// #include <openssl/param_build.h>
import "C"
import (
	"runtime"
	"unsafe"
)

type ParamPair struct {
	key   *C.char
	value *C.char
}
type ParamBld struct {
	bld    *C.OSSL_PARAM_BLD
	params []*ParamPair
}
type Param struct {
	param *C.OSSL_PARAM
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
	param := &ParamPair{ckey, cvalue}

	runtime.SetFinalizer(param, func(p *ParamPair) {
		C.free(unsafe.Pointer(p.key))
		C.free(unsafe.Pointer(p.value))
	})

	if int(C.OSSL_PARAM_BLD_push_utf8_string(p.bld, ckey, cvalue, 0)) != 1 {
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
