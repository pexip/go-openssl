package openssl

// #include <openssl/crypto.h>
// #include <openssl/provider.h>
import "C"
import (
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

var (
	defaultCtx          *LibraryContext = nil
	nonFIPSCtx          *LibraryContext = nil
	nonFIPSLegacyCtx    *LibraryContext = nil
	ErrCreateLibraryCtx                 = errors.New("failed to create library context")
	ErrProviderLoad                     = errors.New("failed to load provider")
)

type LibraryContext struct {
	ctx       *C.OSSL_LIB_CTX
	providers map[string]*C.OSSL_PROVIDER
	mu        *sync.Mutex
}

func loadDefaultProvider() {
	defaultCtx = &LibraryContext{
		ctx: nil, providers: make(map[string]*C.OSSL_PROVIDER), mu: &sync.Mutex{},
	}
	runtime.SetFinalizer(defaultCtx, func(c *LibraryContext) { c.finalise() })
}

func (c *LibraryContext) LoadProvider(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.providers[name]; !exists {
		cname := C.CString(name)
		defer C.free(unsafe.Pointer(cname))
		provider := C.OSSL_PROVIDER_load(c.ctx, cname)
		if provider == nil {
			return ErrProviderLoad
		}
		c.providers[name] = provider
	}
	return nil
}
func (c *LibraryContext) UnloadProvider(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	provider, exists := c.providers[name]
	if !exists {
		return
	}
	C.OSSL_PROVIDER_unload(provider)
	delete(c.providers, name)
}
func (c *LibraryContext) finalise() {
	for p := range c.providers {
		c.UnloadProvider(p)
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
			return nil, ErrCreateLibraryCtx
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
			return nil, ErrCreateLibraryCtx
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
