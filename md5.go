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

type MD5Hash = digestJob

func NewMD5Hash() (*MD5Hash, error) {
	digest, err := GetDigestByName("md5", false)
	if err != nil {
		return nil, err
	}
	return newDigestJob(*digest)
}

func MD5(data []byte) (result [16]byte, err error) {
	hash, err := NewMD5Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if err = hash.Update(data); err != nil {
		return result, err
	}
	resultBuffer, err := hash.Sum()
	if err != nil {
		return result, err
	}
	return *(*[16]byte)(resultBuffer), err
}
