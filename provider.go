package openssl

// #include <openssl/crypto.h>
// #include <openssl/provider.h>
import "C"
import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

var (
	nonFIPSCtx       *LibraryContext = nil
	nonFIPSLegacyCtx *LibraryContext = nil
)

type LibraryContext struct {
	ctx       *C.OSSL_LIB_CTX
	providers map[string]*C.OSSL_PROVIDER
	mu        *sync.Mutex
}

func (c *LibraryContext) LoadProvider(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.providers[name]; !exists {
		cname := C.CString(name)
		defer C.free(unsafe.Pointer(cname))
		provider := C.OSSL_PROVIDER_load(c.ctx, cname)
		if provider == nil {
			return errorFromErrorQueue()
		}
		c.providers[name] = provider
	}
	return nil
}
func (c *LibraryContext) finalise() {
	for _, p := range c.providers {
		C.OSSL_PROVIDER_unload(p)
	}
	if c.ctx != nil {
		C.OSSL_LIB_CTX_free(c.ctx)
		c.ctx = nil
	}
}

// GetNonFIPSCtx gets a non-FIPS context
func GetNonFIPSCtx(withLegacy bool) (*LibraryContext, error) {
	if nonFIPSCtx == nil {
		ctx := C.OSSL_LIB_CTX_new()
		if ctx == nil {
			return nil, fmt.Errorf("foo")
		}
		nonFIPSCtx = &LibraryContext{
			ctx: ctx, providers: make(map[string]*C.OSSL_PROVIDER), mu: &sync.Mutex{},
		}
		runtime.SetFinalizer(nonFIPSCtx, func(c *LibraryContext) { c.finalise() })
		if err := nonFIPSCtx.LoadProvider("default"); err != nil {
			return nil, err
		}
	}
	if nonFIPSLegacyCtx == nil {
		ctx := C.OSSL_LIB_CTX_new()
		if ctx == nil {
			return nil, fmt.Errorf("foo")
		}
		nonFIPSLegacyCtx = &LibraryContext{
			ctx: ctx, providers: make(map[string]*C.OSSL_PROVIDER), mu: &sync.Mutex{},
		}
		runtime.SetFinalizer(nonFIPSLegacyCtx, func(c *LibraryContext) { c.finalise() })
		if err := nonFIPSLegacyCtx.LoadProvider("legacy"); err != nil {
			return nil, err
		}
	}
	if withLegacy {
		return nonFIPSLegacyCtx, nil
	} else {
		return nonFIPSCtx, nil
	}
}
