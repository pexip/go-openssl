// Copyright (C) 2020. See AUTHORS.
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

// #include <openssl/objects.h>
import "C"
import "unsafe"

// CreateObjectIdentifier creates ObjectIdentifier and returns NID for the created
// ObjectIdentifier
func CreateObjectIdentifier(oid string, shortName string, longName string) NID {
	cOid := C.CString(oid)
	defer C.free(unsafe.Pointer(cOid))
	cShortName := C.CString(shortName)
	defer C.free(unsafe.Pointer(cShortName))
	cLongName := C.CString(longName)
	defer C.free(unsafe.Pointer(cLongName))
	return NID(C.OBJ_create(cOid, cShortName, cLongName))
}
