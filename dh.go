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

import "runtime"

// DeriveSharedSecret derives a shared secret using a private key and a peer's
// public key.
// The specific algorithm that is used depends on the types of the
// keys, but it is most commonly a variant of Diffie-Hellman.
func DeriveSharedSecret(private PrivateKey, public PublicKey) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Create context for the shared secret derivation
	ctx, err := NewPKeyDeriveContextFromKey(private)
	if err != nil {
		return nil, err
	}
	if err = ctx.SetPeer(public); err != nil {
		return nil, err
	}
	return ctx.Derive()
}
