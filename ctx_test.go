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
