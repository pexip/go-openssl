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
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func expectError(t *testing.T, err error, expErr error) {
	if err == nil {
		t.Fatalf("Expected error %s, but got none", expErr)
	}
	if !errors.Is(err, expErr) {
		t.Fatalf("Expected error %s, but got %s", expErr, err)
	}
}

func TestBadInputs(t *testing.T) {
	t.Run("GCM 256 invalid key", func(t *testing.T) {
		_, err := NewGCMEncryptionCipherJob(256, []byte("abcdefghijklmnopqrstuvwxyz"), nil)
		expectError(t, err, ErrInvalidKeyLength)
	})
	t.Run("GCM 128 invalid key", func(t *testing.T) {
		_, err := NewGCMEncryptionCipherJob(128, []byte("abcdefghijklmnopqrstuvwxyz"), nil)
		expectError(t, err, ErrInvalidKeyLength)
	})
	t.Run("GCM invalid block size", func(t *testing.T) {
		_, err := NewGCMEncryptionCipherJob(200, []byte("abcdefghijklmnopqrstuvwxy"), nil)
		expectError(t, err, ErrCipherInvalidBlockSize)
	})
	t.Run("invalid IV for cipher", func(t *testing.T) {
		c, err := GetCipherByName("AES-128-CBC", false)
		if err != nil {
			t.Fatal("Could not look up AES-128-CBC")
		}
		_, err = NewCipherJob(c, []byte("abcdefghijklmnop"), []byte("abc"), true)
		expectError(t, err, ErrInvalidIVLength)
	})
}

func doEncryption(key, iv, aad, plaintext []byte, blocksize, bufsize int) (
	ciphertext, tag []byte, err error) {
	ectx, err := NewGCMEncryptionCipherJob(blocksize, key, iv)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed making GCM encryption ctx: %s", err)
	}
	err = ectx.ExtraData(aad)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to add authenticated data: %s",
			err)
	}
	plainb := bytes.NewBuffer(plaintext)
	cipherb := new(bytes.Buffer)
	for plainb.Len() > 0 {
		moar, err := ectx.Update(plainb.Next(bufsize))
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to perform an encryption: %s",
				err)
		}
		cipherb.Write(moar)
	}
	moar, err := ectx.Final()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to finalize encryption: %s", err)
	}
	cipherb.Write(moar)
	tag, err = ectx.GetTag()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get GCM tag: %s", err)
	}
	return cipherb.Bytes(), tag, nil
}

func doDecryption(key, iv, aad, ciphertext, tag []byte, blocksize,
	bufsize int) (plaintext []byte, err error) {
	dctx, err := NewGCMDecryptionCipherCtx(blocksize, key, iv)
	if err != nil {
		return nil, fmt.Errorf("Failed making GCM decryption ctx: %s", err)
	}
	aadbuf := bytes.NewBuffer(aad)
	for aadbuf.Len() > 0 {
		err = dctx.ExtraData(aadbuf.Next(bufsize))
		if err != nil {
			return nil, fmt.Errorf("Failed to add authenticated data: %s", err)
		}
	}
	plainb := new(bytes.Buffer)
	cipherb := bytes.NewBuffer(ciphertext)
	for cipherb.Len() > 0 {
		moar, err := dctx.Update(cipherb.Next(bufsize))
		if err != nil {
			return nil, fmt.Errorf("Failed to perform a decryption: %s", err)
		}
		plainb.Write(moar)
	}
	err = dctx.SetTag(tag)
	if err != nil {
		return nil, fmt.Errorf("Failed to set expected GCM tag: %s", err)
	}
	moar, err := dctx.Final()
	if err != nil {
		return nil, fmt.Errorf("Failed to finalize decryption: %s", err)
	}
	plainb.Write(moar)
	return plainb.Bytes(), nil
}

func checkEqual(t *testing.T, output []byte, original string) {
	output_s := string(output)
	if output_s != original {
		t.Fatalf("output != original! %#v != %#v", output_s, original)
	}
}

func TestGCM(t *testing.T) {
	aad := []byte("foo bar baz")
	key := []byte("nobody can guess this i'm sure..") // len=32
	iv := []byte("a bunch of bytes")
	plaintext := "Long long ago, in a land far away..."

	blocksizes_to_test := []int{256, 192, 128}

	// best for this to have no common factors with blocksize, so that the
	// buffering layer inside the CIPHER_CTX gets exercised
	bufsize := 33

	if len(plaintext)%8 == 0 {
		plaintext += "!" // make sure padding is exercised
	}

	for _, bsize := range blocksizes_to_test {
		t.Run(fmt.Sprintf("AES-%d-GCM", bsize), func(t *testing.T) {
			subkey := key[:bsize/8]
			ciphertext, tag, err := doEncryption(subkey, iv, aad, []byte(plaintext),
				bsize, bufsize)
			if err != nil {
				t.Fatalf("Encryption with b=%d: %s", bsize, err)
			}
			plaintext_out, err := doDecryption(subkey, iv, aad, ciphertext, tag,
				bsize, bufsize)
			if err != nil {
				t.Fatalf("Decryption with b=%d: %s", bsize, err)
			}
			checkEqual(t, plaintext_out, plaintext)
		})
	}
}

func TestGCMWithNoAAD(t *testing.T) {
	key := []byte("0000111122223333")
	iv := []byte("9999")
	plaintext := "ABORT ABORT ABORT DANGAR"

	ciphertext, tag, err := doEncryption(key, iv, nil, []byte(plaintext),
		128, 32)
	if err != nil {
		t.Fatal("Encryption failure:", err)
	}
	plaintext_out, err := doDecryption(key, iv, nil, ciphertext, tag, 128, 129)
	if err != nil {
		t.Fatal("Decryption failure:", err)
	}
	checkEqual(t, plaintext_out, plaintext)
}

func TestBadTag(t *testing.T) {
	key := []byte("abcdefghijklmnop")
	iv := []byte("v7239qjfv3qr793fuaj")
	plaintext := "The red rooster has flown the coop I REPEAT" +
		"the red rooster has flown the coop!!1!"

	ciphertext, tag, err := doEncryption(key, iv, nil, []byte(plaintext),
		128, 32)
	if err != nil {
		t.Fatal("Encryption failure:", err)
	}
	// flip the last bit
	tag[len(tag)-1] ^= 1
	if _, err := doDecryption(key, iv, nil, ciphertext, tag, 128, 129); err == nil {
		t.Fatal("Expected error for bad tag, but got none")
	}
	// flip it back, try again just to make sure
	tag[len(tag)-1] ^= 1
	plaintextOut, err := doDecryption(key, iv, nil, ciphertext, tag, 128, 129)
	if err != nil {
		t.Fatal("Decryption failure:", err)
	}
	checkEqual(t, plaintextOut, plaintext)
}

func TestBadCiphertext(t *testing.T) {
	key := []byte("hard boiled eggs & bacon")
	iv := []byte("x") // it's not a very /good/ IV, is it
	aad := []byte("mu")
	plaintext := "Roger roger bingo charlie, we have a niner fourteen tango"

	ciphertext, tag, err := doEncryption(key, iv, aad, []byte(plaintext),
		192, 1)
	if err != nil {
		t.Fatal("Encryption failure:", err)
	}
	// flip the last bit
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := doDecryption(key, iv, aad, ciphertext, tag, 192, 192); err == nil {
		t.Fatal("Expected error for bad ciphertext, but got none")
	}
	// flip it back, try again just to make sure
	ciphertext[len(ciphertext)-1] ^= 1
	plaintextOut, err := doDecryption(key, iv, aad, ciphertext, tag, 192, 192)
	if err != nil {
		t.Fatal("Decryption failure:", err)
	}
	checkEqual(t, plaintextOut, plaintext)
}

func TestBadAAD(t *testing.T) {
	key := []byte("Ive got a lovely buncha coconuts")
	iv := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab")
	aad := []byte("Hi i am a plain")
	plaintext := "Whatever."

	ciphertext, tag, err := doEncryption(key, iv, aad, []byte(plaintext),
		256, 256)
	if err != nil {
		t.Fatal("Encryption failure:", err)
	}
	// flip the last bit
	aad[len(aad)-1] ^= 1
	if _, err := doDecryption(key, iv, aad, ciphertext, tag, 256, 256); err == nil {
		t.Fatal("Expected error for bad AAD, but got none")
	}
	// flip it back, try again just to make sure
	aad[len(aad)-1] ^= 1
	plaintextOut, err := doDecryption(key, iv, aad, ciphertext, tag, 256, 256)
	if err != nil {
		t.Fatal("Decryption failure:", err)
	}
	checkEqual(t, plaintextOut, plaintext)
}

func TestNonAuthenticatedEncryption(t *testing.T) {
	key := []byte("never gonna give you up, never g")
	iv := []byte("onna let you dow")
	plaintext1 := "n, never gonna run around"
	plaintext2 := " and desert you"

	cipher, err := GetCipherByName("aes-256-cbc", false)
	if err != nil {
		t.Fatal("Could not get cipher: ", err)
	}

	eCtx, err := NewCipherJob(cipher, key, iv, true)
	if err != nil {
		t.Fatal("Could not create encryption context: ", err)
	}
	cipherbytes, err := eCtx.Update([]byte(plaintext1))
	if err != nil {
		t.Fatal("EncryptUpdate(plaintext1) failure: ", err)
	}
	ciphertext := string(cipherbytes)
	cipherbytes, err = eCtx.Update([]byte(plaintext2))
	if err != nil {
		t.Fatal("EncryptUpdate(plaintext2) failure: ", err)
	}
	ciphertext += string(cipherbytes)
	cipherbytes, err = eCtx.Final()
	if err != nil {
		t.Fatal("EncryptFinal() failure: ", err)
	}
	ciphertext += string(cipherbytes)

	dCtx, err := NewCipherJob(cipher, key, iv, false)
	if err != nil {
		t.Fatal("Could not create decryption context: ", err)
	}
	plainbytes, err := dCtx.Update([]byte(ciphertext[:15]))
	if err != nil {
		t.Fatal("DecryptUpdate(ciphertext part 1) failure: ", err)
	}
	plainOutput := string(plainbytes)
	plainbytes, err = dCtx.Update([]byte(ciphertext[15:]))
	if err != nil {
		t.Fatal("DecryptUpdate(ciphertext part 2) failure: ", err)
	}
	plainOutput += string(plainbytes)
	plainbytes, err = dCtx.Final()
	if err != nil {
		t.Fatal("DecryptFinal() failure: ", err)
	}
	plainOutput += string(plainbytes)

	checkEqual(t, []byte(plainOutput), plaintext1+plaintext2)
}

func TestCipherJobGetCipher(t *testing.T) {
	cipher, err := GetCipherByName("aes-256-cbc", false)
	if err != nil {
		t.Fatal("Could not get cipher: ", err)
	}
	job, err := NewCipherJob(cipher, []byte("12345678123456781234567812345678"), nil, true)
	if err != nil {
		t.Fatal("Could not create cipher job: ", err)
	}
	fetchedCipher := job.Cipher()
	if fetchedCipher.name != "AES-256-CBC" {
		t.Fatalf("Got invalid cipher name: %s", fetchedCipher.name)
	}
}
