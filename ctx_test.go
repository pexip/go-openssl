// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"strings"
	"testing"
	"time"
)

func TestCtxTimeoutOption(t *testing.T) {
	ctx, _ := NewCtx()
	oldTimeout1 := ctx.GetTimeout()
	newTimeout1 := oldTimeout1 + (time.Duration(99) * time.Second)
	oldTimeout2 := ctx.SetTimeout(newTimeout1)
	newTimeout2 := ctx.GetTimeout()
	if oldTimeout1 != oldTimeout2 {
		t.Error("SetTimeout() returns something undocumented")
	}
	if newTimeout1 != newTimeout2 {
		t.Error("SetTimeout() does not save anything to ctx")
	}
}

func TestCtxSessCacheSizeOption(t *testing.T) {
	ctx, _ := NewCtx()
	oldSize1 := ctx.GetSessionCacheSize()
	newSize1 := oldSize1 + 42
	oldSize2 := ctx.SetSessionCacheSize(newSize1)
	newSize2 := ctx.GetSessionCacheSize()
	if oldSize1 != oldSize2 {
		t.Error("SetSessionCacheSize() returns something undocumented")
	}
	if newSize1 != newSize2 {
		t.Error("SetSessionCacheSize() does not save anything to ctx")
	}
}

func TestCtxSetCipherSuites(t *testing.T) {
	ctx, _ := NewCtx()

	t.Run("valid cipher suite", func(t *testing.T) {
		err := ctx.SetCipherSuites("TLS_AES_128_GCM_SHA256")
		if err != nil {
			t.Error("SetCipherSuites() returned unexpected error")
			return
		}
	})

	t.Run("invalid cipher suite", func(t *testing.T) {
		err := ctx.SetCipherSuites("invalid")
		if err == nil {
			t.Error("SetCipherSuites() did not return expected error")
			return
		}

		if !strings.Contains(err.Error(), "no cipher match") {
			t.Error("SetCipherSuites() did not return expected error")
		}
	})
}

func TestCtxSetGroupsList(t *testing.T) {
	ctx, _ := NewCtx()

	t.Run("invalid group", func(t *testing.T) {
		err := ctx.SetGroupsList("")
		if err == nil {
			t.Error("SetGroupsList() did not return expected error")
			return
		}

		if !strings.Contains(err.Error(), "ssl error") {
			t.Error("SetGroupsList() did not return expected error")
			return
		}
	})

	t.Run("valid group", func(t *testing.T) {
		err := ctx.SetGroupsList("P-256:P-384:P-521")
		if err != nil {
			t.Error("SetGroupsList() returned unexpected error")
			return
		}
	})
}

func TestCtxSecurityLevel(t *testing.T) {
	ctx, _ := NewCtx()

	// Security levels are 0 - 5
	// https://docs.openssl.org/master/man3/SSL_CTX_set_security_level
	t.Run("valid security levels", func(t *testing.T) {
		for i := 0; i <= 5; i++ {
			ctx.SetSecurityLevel(i)
			secLevel := ctx.GetSecurityLevel()
			if secLevel != i {
				t.Errorf("SetSecurityLevel(%d) failed on GetSecurityLevel()", i)
			}
		}
	})

	t.Run("security level too low", func(t *testing.T) {
		ctx.SetSecurityLevel(-1)
		if ctx.GetSecurityLevel() == -1 {
			t.Error("SetSecurityLevel(-1) should not be allowed")
		}

	})

	t.Run("security level too high", func(t *testing.T) {
		ctx.SetSecurityLevel(6)
		if ctx.GetSecurityLevel() == 6 {
			t.Error("SetSecurityLevel(6) should not be allowed")
		}
	})
}
