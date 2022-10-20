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
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pexip/go-openssl/utils"
)

var (
	certBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUYYC8EshUsBUeU6IG2Fyr1Nr7KG0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxEDAOBgNVBAcMB01pZHZh
bGUxFTATBgNVBAoMDFNwYWNlIE1vbmtleTAeFw0yMTA4MTQxODIzNDFaFw0zMTA2
MjMxODIzNDFaMEUxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRAwDgYDVQQH
DAdNaWR2YWxlMRUwEwYDVQQKDAxTcGFjZSBNb25rZXkwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDdf3icNvFsrlrnNLi8SocscqlSbFq+pEvmhcSoqgDL
qebnqu8Ld73HJJ74MGXEgRX8xZT5FinOML31CR6t9E/j3dqV6p+GfdlFLe3IqtC0
/bPVnCDBirBygBI4uCrMq+1VhAxPWclrDo7l9QRYbsExH9lfn+RyvxeNMZiOASas
vVZNncY8E9usBGRdH17EfDL/TPwXqWOLyxSN5o54GTztjjy9w9CGQP7jcCueKYyQ
JQCtEmnwc6P/q6/EPv5R6drBkX6loAPtmCUAkHqxkWOJrRq/v7PwzRYhfY+ZpVHG
c7WEkDnLzRiUypr1C9oxvLKS10etZEIwEdKyOkSg2fdPAgMBAAGjUzBRMB0GA1Ud
DgQWBBSj8Z6d2TqacRP4allwQM1FYgltPzAfBgNVHSMEGDAWgBSj8Z6d2TqacRP4
allwQM1FYgltPzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA2
KJLoFWorZz+tb/HdDJTTDxy5/XhOnx+2OIALFsLJnulo8fHbJnPKspe2V08EcFZ0
hUrvKsaXpm8VXX21yOFg5yMcrG6A3voQWIjvTCNwfywnpnsxrWwhuRqioUmR4WSW
NoFuwg+lt6bLDavM4Izl86Nb/LoAzKc6g6nKGHKJLuJma6RPJnmjfC4Os1GWf7rf
kQOP/XdA0t+JW1+ABBdOd5kOtowAvQLKzLYi6xTrvEDSjDtiKS42dVydBpj3Uaih
tCzcieQbb6KqUyxxzgTelXq2IxJUyU74Jv96BZ8cA7Qvwv1jwsfxYv7VHLuFAmtW
KCDFmLjMtdrKX+q5zJe7
-----END CERTIFICATE-----
`)
	certDerBytes = []byte{
		0x30, 0x82, 0x03, 0x6b, 0x30, 0x82, 0x02, 0x53, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x61, 0x80, 0xbc, 0x12,
		0xc8, 0x54, 0xb0, 0x15, 0x1e, 0x53, 0xa2, 0x06, 0xd8, 0x5c, 0xab, 0xd4, 0xda, 0xfb, 0x28, 0x6d, 0x30, 0x0d, 0x06,
		0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06,
		0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x04,
		0x55, 0x74, 0x61, 0x68, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x4d, 0x69, 0x64, 0x76,
		0x61, 0x6c, 0x65, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x53, 0x70, 0x61, 0x63, 0x65,
		0x20, 0x4d, 0x6f, 0x6e, 0x6b, 0x65, 0x79, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x38, 0x31, 0x34, 0x31, 0x38,
		0x32, 0x33, 0x34, 0x31, 0x5a, 0x17, 0x0d, 0x33, 0x31, 0x30, 0x36, 0x32, 0x33, 0x31, 0x38, 0x32, 0x33, 0x34, 0x31,
		0x5a, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0d, 0x30,
		0x0b, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x04, 0x55, 0x74, 0x61, 0x68, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
		0x04, 0x07, 0x0c, 0x07, 0x4d, 0x69, 0x64, 0x76, 0x61, 0x6c, 0x65, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
		0x0a, 0x0c, 0x0c, 0x53, 0x70, 0x61, 0x63, 0x65, 0x20, 0x4d, 0x6f, 0x6e, 0x6b, 0x65, 0x79, 0x30, 0x82, 0x01, 0x22,
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
		0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdd, 0x7f, 0x78, 0x9c, 0x36, 0xf1, 0x6c, 0xae, 0x5a,
		0xe7, 0x34, 0xb8, 0xbc, 0x4a, 0x87, 0x2c, 0x72, 0xa9, 0x52, 0x6c, 0x5a, 0xbe, 0xa4, 0x4b, 0xe6, 0x85, 0xc4, 0xa8,
		0xaa, 0x00, 0xcb, 0xa9, 0xe6, 0xe7, 0xaa, 0xef, 0x0b, 0x77, 0xbd, 0xc7, 0x24, 0x9e, 0xf8, 0x30, 0x65, 0xc4, 0x81,
		0x15, 0xfc, 0xc5, 0x94, 0xf9, 0x16, 0x29, 0xce, 0x30, 0xbd, 0xf5, 0x09, 0x1e, 0xad, 0xf4, 0x4f, 0xe3, 0xdd, 0xda,
		0x95, 0xea, 0x9f, 0x86, 0x7d, 0xd9, 0x45, 0x2d, 0xed, 0xc8, 0xaa, 0xd0, 0xb4, 0xfd, 0xb3, 0xd5, 0x9c, 0x20, 0xc1,
		0x8a, 0xb0, 0x72, 0x80, 0x12, 0x38, 0xb8, 0x2a, 0xcc, 0xab, 0xed, 0x55, 0x84, 0x0c, 0x4f, 0x59, 0xc9, 0x6b, 0x0e,
		0x8e, 0xe5, 0xf5, 0x04, 0x58, 0x6e, 0xc1, 0x31, 0x1f, 0xd9, 0x5f, 0x9f, 0xe4, 0x72, 0xbf, 0x17, 0x8d, 0x31, 0x98,
		0x8e, 0x01, 0x26, 0xac, 0xbd, 0x56, 0x4d, 0x9d, 0xc6, 0x3c, 0x13, 0xdb, 0xac, 0x04, 0x64, 0x5d, 0x1f, 0x5e, 0xc4,
		0x7c, 0x32, 0xff, 0x4c, 0xfc, 0x17, 0xa9, 0x63, 0x8b, 0xcb, 0x14, 0x8d, 0xe6, 0x8e, 0x78, 0x19, 0x3c, 0xed, 0x8e,
		0x3c, 0xbd, 0xc3, 0xd0, 0x86, 0x40, 0xfe, 0xe3, 0x70, 0x2b, 0x9e, 0x29, 0x8c, 0x90, 0x25, 0x00, 0xad, 0x12, 0x69,
		0xf0, 0x73, 0xa3, 0xff, 0xab, 0xaf, 0xc4, 0x3e, 0xfe, 0x51, 0xe9, 0xda, 0xc1, 0x91, 0x7e, 0xa5, 0xa0, 0x03, 0xed,
		0x98, 0x25, 0x00, 0x90, 0x7a, 0xb1, 0x91, 0x63, 0x89, 0xad, 0x1a, 0xbf, 0xbf, 0xb3, 0xf0, 0xcd, 0x16, 0x21, 0x7d,
		0x8f, 0x99, 0xa5, 0x51, 0xc6, 0x73, 0xb5, 0x84, 0x90, 0x39, 0xcb, 0xcd, 0x18, 0x94, 0xca, 0x9a, 0xf5, 0x0b, 0xda,
		0x31, 0xbc, 0xb2, 0x92, 0xd7, 0x47, 0xad, 0x64, 0x42, 0x30, 0x11, 0xd2, 0xb2, 0x3a, 0x44, 0xa0, 0xd9, 0xf7, 0x4f,
		0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
		0x14, 0xa3, 0xf1, 0x9e, 0x9d, 0xd9, 0x3a, 0x9a, 0x71, 0x13, 0xf8, 0x6a, 0x59, 0x70, 0x40, 0xcd, 0x45, 0x62, 0x09,
		0x6d, 0x3f, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xa3, 0xf1, 0x9e, 0x9d,
		0xd9, 0x3a, 0x9a, 0x71, 0x13, 0xf8, 0x6a, 0x59, 0x70, 0x40, 0xcd, 0x45, 0x62, 0x09, 0x6d, 0x3f, 0x30, 0x0f, 0x06,
		0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a,
		0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x36, 0x28, 0x92, 0xe8,
		0x15, 0x6a, 0x2b, 0x67, 0x3f, 0xad, 0x6f, 0xf1, 0xdd, 0x0c, 0x94, 0xd3, 0x0f, 0x1c, 0xb9, 0xfd, 0x78, 0x4e, 0x9f,
		0x1f, 0xb6, 0x38, 0x80, 0x0b, 0x16, 0xc2, 0xc9, 0x9e, 0xe9, 0x68, 0xf1, 0xf1, 0xdb, 0x26, 0x73, 0xca, 0xb2, 0x97,
		0xb6, 0x57, 0x4f, 0x04, 0x70, 0x56, 0x74, 0x85, 0x4a, 0xef, 0x2a, 0xc6, 0x97, 0xa6, 0x6f, 0x15, 0x5d, 0x7d, 0xb5,
		0xc8, 0xe1, 0x60, 0xe7, 0x23, 0x1c, 0xac, 0x6e, 0x80, 0xde, 0xfa, 0x10, 0x58, 0x88, 0xef, 0x4c, 0x23, 0x70, 0x7f,
		0x2c, 0x27, 0xa6, 0x7b, 0x31, 0xad, 0x6c, 0x21, 0xb9, 0x1a, 0xa2, 0xa1, 0x49, 0x91, 0xe1, 0x64, 0x96, 0x36, 0x81,
		0x6e, 0xc2, 0x0f, 0xa5, 0xb7, 0xa6, 0xcb, 0x0d, 0xab, 0xcc, 0xe0, 0x8c, 0xe5, 0xf3, 0xa3, 0x5b, 0xfc, 0xba, 0x00,
		0xcc, 0xa7, 0x3a, 0x83, 0xa9, 0xca, 0x18, 0x72, 0x89, 0x2e, 0xe2, 0x66, 0x6b, 0xa4, 0x4f, 0x26, 0x79, 0xa3, 0x7c,
		0x2e, 0x0e, 0xb3, 0x51, 0x96, 0x7f, 0xba, 0xdf, 0x91, 0x03, 0x8f, 0xfd, 0x77, 0x40, 0xd2, 0xdf, 0x89, 0x5b, 0x5f,
		0x80, 0x04, 0x17, 0x4e, 0x77, 0x99, 0x0e, 0xb6, 0x8c, 0x00, 0xbd, 0x02, 0xca, 0xcc, 0xb6, 0x22, 0xeb, 0x14, 0xeb,
		0xbc, 0x40, 0xd2, 0x8c, 0x3b, 0x62, 0x29, 0x2e, 0x36, 0x75, 0x5c, 0x9d, 0x06, 0x98, 0xf7, 0x51, 0xa8, 0xa1, 0xb4,
		0x2c, 0xdc, 0x89, 0xe4, 0x1b, 0x6f, 0xa2, 0xaa, 0x53, 0x2c, 0x71, 0xce, 0x04, 0xde, 0x95, 0x7a, 0xb6, 0x23, 0x12,
		0x54, 0xc9, 0x4e, 0xf8, 0x26, 0xff, 0x7a, 0x05, 0x9f, 0x1c, 0x03, 0xb4, 0x2f, 0xc2, 0xfd, 0x63, 0xc2, 0xc7, 0xf1,
		0x62, 0xfe, 0xd5, 0x1c, 0xbb, 0x85, 0x02, 0x6b, 0x56, 0x28, 0x20, 0xc5, 0x98, 0xb8, 0xcc, 0xb5, 0xda, 0xca, 0x5f,
		0xea, 0xb9, 0xcc, 0x97, 0xbb,
	}
	keyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA3X94nDbxbK5a5zS4vEqHLHKpUmxavqRL5oXEqKoAy6nm56rv
C3e9xySe+DBlxIEV/MWU+RYpzjC99QkerfRP493aleqfhn3ZRS3tyKrQtP2z1Zwg
wYqwcoASOLgqzKvtVYQMT1nJaw6O5fUEWG7BMR/ZX5/kcr8XjTGYjgEmrL1WTZ3G
PBPbrARkXR9exHwy/0z8F6lji8sUjeaOeBk87Y48vcPQhkD+43ArnimMkCUArRJp
8HOj/6uvxD7+UenawZF+paAD7ZglAJB6sZFjia0av7+z8M0WIX2PmaVRxnO1hJA5
y80YlMqa9QvaMbyyktdHrWRCMBHSsjpEoNn3TwIDAQABAoIBAQCwgp6YzmgCFce3
LBpzYmjqEM3CMzr1ZXRe1gbr6d4Mbu7leyBX4SpJAnP0kIzo1X2yG7ol7XWPLOST
2pqqQWFQ00EX6wsJYEy+hmVRXl5HfU3MUkkAMwd9l3Xt4UWqKPBPD5XHvmN2fvl9
Y4388vXdseXGAGNK1eFs0TMjJuOtDxDyrmJcnxpJ7y/77y/Hb5rUa9DCvj8tkKHg
HmeIwQE0HhIFofj+qCYbqeVyjbPAaYZMrISXb2HmcyULKEOGRbMH24IzInKA0NxV
kdP9qmV8Y2bJ609Fft/y8Vpj31iEdq/OFXyobdVvnXMnaVyAetoaWy7AOTIQ2Cnw
wGbJ/F8BAoGBAN/pCnLQrWREeVMuFjf+MgYgCtRRaQ8EOVvjYcXXi0PhtOMFTAb7
djqhlgmBOFsmeXcb8YRZsF+pNtu1xk5RJOquyKfK8j1rUdAJfoxGHiaUFI2/1i9E
zuXX/Ao0xNRkWMxMKuwYBmmt1fMuVo+1M8UEwFMdHRtgxe+/+eOV1J2PAoGBAP09
7GLOYSYAI1OO3BN/bEVNau6tAxP5YShGmX2Qxy0+ooxHZ1V3D8yo6C0hSg+H+fPT
mjMgGcvaW6K+QyCdHDjgbk2hfdZ+Beq92JApPrH9gMV7MPhwHzgwjzDDio9OFxYY
3vjBQ2yX+9jvz9lkvq2NM3fqFqbsG6Et+5mCc6pBAoGBAI62bxVtEgbladrtdfXs
S6ABzkUzOl362EBL9iZuUnJKqstDtgiBQALwuLuIJA5cwHB9W/t6WuMt7CwveJy0
NW5rRrNDtBAXlgad9o2bp135ZfxO+EoadjCi8B7lMUsaRkq4hWcDjRrQVJxxvXRN
DxkVBSw0Uzf+/0nnN3OqLODbAoGACCY+/isAC1YDzQOS53m5RT2pjEa7C6CB1Ob4
t4a6MiWK25LMq35qXr6swg8JMBjDHWqY0r5ctievvTv8Mwd7SgVG526j+wwRKq2z
U2hQYS/0Peap+8S37Hn7kakpQ1VS/t4MBttJTSxS6XdGLAvG6xTZLCm3UuXUOcqe
ByGgkUECgYEAmop45kRi974g4MPvyLplcE4syb19ifrHj76gPRBi94Cp8jZosY1T
ucCCa4lOGgPtXJ0Qf1c8yq5vh4yqkQjrgUTkr+CFDGR6y4CxmNDQxEMYIajaIiSY
qmgvgyRayemfO2zR0CPgC6wSoGBth+xW6g+WA8y0z76ZSaWpFi8lVM4=
-----END RSA PRIVATE KEY-----
`)
	prime256v1KeyBytes = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIB/XL0zZSsAu+IQF1AI/nRneabb2S126WFlvvhzmYr1KoAoGCCqGSM49
AwEHoUQDQgAESSFGWwF6W1hoatKGPPorh4+ipyk0FqpiWdiH+4jIiU39qtOeZGSh
1QgSbzfdHxvoYI0FXM+mqE7wec0kIvrrHw==
-----END EC PRIVATE KEY-----
`)
	prime256v1CertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIChTCCAiqgAwIBAgIJAOQII2LQl4uxMAoGCCqGSM49BAMCMIGcMQswCQYDVQQG
EwJVUzEPMA0GA1UECAwGS2Fuc2FzMRAwDgYDVQQHDAdOb3doZXJlMR8wHQYDVQQK
DBZGYWtlIENlcnRpZmljYXRlcywgSW5jMUkwRwYDVQQDDEBhMWJkZDVmZjg5ZjQy
N2IwZmNiOTdlNDMyZTY5Nzg2NjI2ODJhMWUyNzM4MDhkODE0ZWJiZjY4ODBlYzA3
NDljMB4XDTE3MTIxNTIwNDU1MVoXDTI3MTIxMzIwNDU1MVowgZwxCzAJBgNVBAYT
AlVTMQ8wDQYDVQQIDAZLYW5zYXMxEDAOBgNVBAcMB05vd2hlcmUxHzAdBgNVBAoM
FkZha2UgQ2VydGlmaWNhdGVzLCBJbmMxSTBHBgNVBAMMQGExYmRkNWZmODlmNDI3
YjBmY2I5N2U0MzJlNjk3ODY2MjY4MmExZTI3MzgwOGQ4MTRlYmJmNjg4MGVjMDc0
OWMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARJIUZbAXpbWGhq0oY8+iuHj6Kn
KTQWqmJZ2If7iMiJTf2q055kZKHVCBJvN90fG+hgjQVcz6aoTvB5zSQi+usfo1Mw
UTAdBgNVHQ4EFgQUfRYAFhlGM1wzvusyGrm26Vrbqm4wHwYDVR0jBBgwFoAUfRYA
FhlGM1wzvusyGrm26Vrbqm4wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJ
ADBGAiEA6PWNjm4B6zs3Wcha9qyDdfo1ILhHfk9rZEAGrnfyc2UCIQD1IDVJUkI4
J/QVoOtP5DOdRPs/3XFy0Bk0qH+Uj5D7LQ==
-----END CERTIFICATE-----
`)
	ed25519CertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIBIzCB1gIUd0UUPX+qHrSKSVN9V/A3F1Eeti4wBQYDK2VwMDYxCzAJBgNVBAYT
AnVzMQ0wCwYDVQQKDARDU0NPMRgwFgYDVQQDDA9lZDI1NTE5X3Jvb3RfY2EwHhcN
MTgwODE3MDMzNzQ4WhcNMjgwODE0MDMzNzQ4WjAzMQswCQYDVQQGEwJ1czENMAsG
A1UECgwEQ1NDTzEVMBMGA1UEAwwMZWQyNTUxOV9sZWFmMCowBQYDK2VwAyEAKZZJ
zzlBcpjdbvzV0BRoaSiJKxbU6GnFeAELA0cHWR0wBQYDK2VwA0EAbfUJ7L7v3GDq
Gv7R90wQ/OKAc+o0q9eOrD6KRYDBhvlnMKqTMRVucnHXfrd5Rhmf4yHTvFTOhwmO
t/hpmISAAA==
-----END CERTIFICATE-----
`)
	ed25519KeyBytes = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL3QVwyuusKuLgZwZn356UHk9u1REGHbNTLtFMPKNQSb
-----END PRIVATE KEY-----
`)
)

func NetPipe(t testing.TB) (net.Conn, net.Conn) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client_future := utils.NewFuture()
	go func() {
		client_future.Set(net.Dial(l.Addr().Network(), l.Addr().String()))
	}()
	var errs utils.ErrorGroup
	server_conn, err := l.Accept()
	errs.Add(err)
	client_conn, err := client_future.Get()
	errs.Add(err)
	err = errs.Finalize()
	if err != nil {
		if server_conn != nil {
			server_conn.Close()
		}
		if client_conn != nil {
			client_conn.(net.Conn).Close()
		}
		t.Fatal(err)
	}
	return server_conn, client_conn.(net.Conn)
}

type HandshakingConn interface {
	net.Conn
	Handshake() error
}

func SimpleConnTest(t testing.TB, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn)) {
	server_conn, client_conn := NetPipe(t)
	defer server_conn.Close()
	defer client_conn.Close()

	data := "first test string\n"

	server, client := constructor(t, server_conn, client_conn)
	defer close_both(server, client)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()

		err := client.Handshake()
		if err != nil {
			t.Fatal(err)
		}

		_, err = io.Copy(client, bytes.NewReader([]byte(data)))
		if err != nil {
			t.Fatal(err)
		}

		err = client.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()
	go func() {
		defer wg.Done()

		err := server.Handshake()
		if err != nil {
			t.Fatal(err)
		}

		buf := bytes.NewBuffer(make([]byte, 0, len(data)))
		_, err = io.Copy(buf, server)
		if err != nil {
			t.Fatal(err)
		}
		if buf.String() != data {
			t.Fatal("mismatched data")
		}

		// Only one side gets a clean close because closing needs to write a terminator.
		_ = server.Close()
	}()
	wg.Wait()
}

func close_both(closer1, closer2 io.Closer) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		closer1.Close()
	}()
	go func() {
		defer wg.Done()
		closer2.Close()
	}()
	wg.Wait()
}

func ClosingTest(t *testing.T, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn)) {

	run_test := func(t *testing.T, close_tcp bool, server_writes bool) {
		server_conn, client_conn := NetPipe(t)
		defer server_conn.Close()
		defer client_conn.Close()
		server, client := constructor(t, server_conn, client_conn)
		defer close_both(server, client)

		var sslconn1, sslconn2 HandshakingConn
		var conn1 net.Conn
		if server_writes {
			sslconn1 = server
			conn1 = server_conn
			sslconn2 = client
		} else {
			sslconn1 = client
			conn1 = client_conn
			sslconn2 = server
		}

		var wg sync.WaitGroup

		// If we're killing the TCP connection, make sure we handshake first
		if close_tcp {
			wg.Add(2)
			go func() {
				defer wg.Done()
				err := sslconn1.Handshake()
				if err != nil {
					t.Error(err)
				}
			}()
			go func() {
				defer wg.Done()
				err := sslconn2.Handshake()
				if err != nil {
					t.Error(err)
				}
			}()
			wg.Wait()
		}

		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := sslconn1.Write([]byte("hello"))
			if err != nil {
				t.Error(err)
				return
			}
			if close_tcp {
				err = conn1.Close()
			} else {
				err = sslconn1.Close()
			}
			if err != nil {
				t.Error(err)
			}
		}()

		go func() {
			defer wg.Done()
			data, err := io.ReadAll(sslconn2)
			if !bytes.Equal(data, []byte("hello")) {
				t.Error("bytes don't match")
			}
			if !close_tcp && err != nil {
				t.Error(err)
				return
			}
		}()

		wg.Wait()
	}

	t.Run("close TCP, server reads", func(t *testing.T) {
		run_test(t, true, false)
	})
	t.Run("close SSL, server reads", func(t *testing.T) {
		run_test(t, false, false)
	})
	t.Run("close TCP, server writes", func(t *testing.T) {
		run_test(t, true, true)
	})
	t.Run("close SSL, server writes", func(t *testing.T) {
		run_test(t, false, true)
	})
}

func ThroughputBenchmark(b *testing.B, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn)) {
	server_conn, client_conn := NetPipe(b)
	defer server_conn.Close()
	defer client_conn.Close()

	server, client := constructor(b, server_conn, client_conn)
	defer close_both(server, client)

	b.SetBytes(1024)
	data := make([]byte, b.N*1024)
	_, err := io.ReadFull(rand.Reader, data[:])
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err = io.Copy(client, bytes.NewReader(data)); err != nil {
			b.Error(err)
			return
		}
	}()
	go func() {
		defer wg.Done()

		buf := &bytes.Buffer{}
		if _, err = io.CopyN(buf, server, int64(len(data))); err != nil {
			b.Error(err)
			return
		}
		if !bytes.Equal(buf.Bytes(), data) {
			b.Error("mismatched data")
		}
	}()
	wg.Wait()
	b.StopTimer()
}

func StdlibConstructor(t testing.TB, server_conn, client_conn net.Conn) (
	server, client HandshakingConn) {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
	server = tls.Server(server_conn, config)
	client = tls.Client(client_conn, config)
	return server, client
}

func passThruVerify(t testing.TB) func(bool, *CertificateStoreCtx) bool {
	x := func(ok bool, store *CertificateStoreCtx) bool {
		cert := store.GetCurrentCert()
		if cert == nil {
			t.Fatalf("Could not obtain cert from store\n")
		}
		sn := cert.GetSerialNumberHex()
		if len(sn) == 0 {
			t.Fatalf("Could not obtain serial number from cert")
		}
		return ok
	}
	return x
}

func OpenSSLConstructor(t testing.TB, server_conn, client_conn net.Conn) (
	server, client HandshakingConn) {
	ctx, err := NewCtx()
	if err != nil {
		t.Fatal(err)
	}
	ctx.SetVerify(VerifyNone, passThruVerify(t))
	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.UsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.UseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	err = ctx.SetCipherList("AES128-SHA")
	if err != nil {
		t.Fatal(err)
	}
	server, err = Server(server_conn, ctx)
	if err != nil {
		t.Fatal(err)
	}
	client, err = Client(client_conn, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

func StdlibOpenSSLConstructor(t testing.TB, server_conn, client_conn net.Conn) (
	server, client HandshakingConn) {
	server_std, _ := StdlibConstructor(t, server_conn, client_conn)
	_, client_ssl := OpenSSLConstructor(t, server_conn, client_conn)
	return server_std, client_ssl
}

func OpenSSLStdlibConstructor(t testing.TB, server_conn, client_conn net.Conn) (
	server, client HandshakingConn) {
	_, client_std := StdlibConstructor(t, server_conn, client_conn)
	server_ssl, _ := OpenSSLConstructor(t, server_conn, client_conn)
	return server_ssl, client_std
}

func TestStdlibSimple(t *testing.T) {
	SimpleConnTest(t, StdlibConstructor)
}

func TestOpenSSLSimple(t *testing.T) {
	SimpleConnTest(t, OpenSSLConstructor)
}

func TestStdlibClosing(t *testing.T) {
	ClosingTest(t, StdlibConstructor)
}

func TestOpenSSLClosing(t *testing.T) {
	ClosingTest(t, OpenSSLConstructor)
}

func BenchmarkStdlibThroughput(b *testing.B) {
	ThroughputBenchmark(b, StdlibConstructor)
}

func BenchmarkOpenSSLThroughput(b *testing.B) {
	ThroughputBenchmark(b, OpenSSLConstructor)
}

func TestStdlibOpenSSLSimple(t *testing.T) {
	SimpleConnTest(t, StdlibOpenSSLConstructor)
}

func TestOpenSSLStdlibSimple(t *testing.T) {
	SimpleConnTest(t, OpenSSLStdlibConstructor)
}

func TestStdlibOpenSSLClosing(t *testing.T) {
	ClosingTest(t, StdlibOpenSSLConstructor)
}

func TestOpenSSLStdlibClosing(t *testing.T) {
	ClosingTest(t, OpenSSLStdlibConstructor)
}

func BenchmarkStdlibOpenSSLThroughput(b *testing.B) {
	ThroughputBenchmark(b, StdlibOpenSSLConstructor)
}

func BenchmarkOpenSSLStdlibThroughput(b *testing.B) {
	ThroughputBenchmark(b, OpenSSLStdlibConstructor)
}

func FullDuplexRenegotiationTest(t testing.TB, constructor func(
	t testing.TB, conn1, conn2 net.Conn) (sslconn1, sslconn2 HandshakingConn)) {

	server_conn, client_conn := NetPipe(t)
	defer server_conn.Close()
	defer client_conn.Close()

	times := 256
	data_len := 4 * SSLRecordSize
	data1 := make([]byte, data_len)
	_, err := io.ReadFull(rand.Reader, data1[:])
	if err != nil {
		t.Fatal(err)
	}
	data2 := make([]byte, data_len)
	_, err = io.ReadFull(rand.Reader, data1[:])
	if err != nil {
		t.Fatal(err)
	}

	server, client := constructor(t, server_conn, client_conn)
	defer close_both(server, client)

	var wg sync.WaitGroup

	send_func := func(sender HandshakingConn, data []byte) {
		defer wg.Done()
		for i := 0; i < times; i++ {
			if i == times/2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					err := sender.Handshake()
					if err != nil {
						t.Fatal(err)
					}
				}()
			}
			_, err := sender.Write(data)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	recv_func := func(receiver net.Conn, data []byte) {
		defer wg.Done()

		buf := make([]byte, len(data))
		for i := 0; i < times; i++ {
			n, err := io.ReadFull(receiver, buf[:])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], data) {
				t.Fatal(err)
			}
		}
	}

	wg.Add(4)
	go recv_func(server, data1)
	go send_func(client, data1)
	go send_func(server, data2)
	go recv_func(client, data2)
	wg.Wait()
}

func TestStdlibFullDuplexRenegotiation(t *testing.T) {
	FullDuplexRenegotiationTest(t, StdlibConstructor)
}

func TestOpenSSLFullDuplexRenegotiation(t *testing.T) {
	FullDuplexRenegotiationTest(t, OpenSSLConstructor)
}

func TestOpenSSLStdlibFullDuplexRenegotiation(t *testing.T) {
	FullDuplexRenegotiationTest(t, OpenSSLStdlibConstructor)
}

func TestStdlibOpenSSLFullDuplexRenegotiation(t *testing.T) {
	FullDuplexRenegotiationTest(t, StdlibOpenSSLConstructor)
}

func LotsOfConns(t *testing.T, payload_size int64, loops, clients int,
	sleep time.Duration, newListener func(net.Listener) net.Listener,
	newClient func(net.Conn) (net.Conn, error)) {
	tcp_listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	ssl_listener := newListener(tcp_listener)
	go func() {
		for {
			conn, err := ssl_listener.Accept()
			if err != nil {
				t.Errorf("failed accept: %s", err)
				continue
			}
			go func() {
				defer func() {
					err = conn.Close()
					if err != nil {
						t.Errorf("failed closing: %s", err)
					}
				}()
				for i := 0; i < loops; i++ {
					_, err := io.Copy(io.Discard,
						io.LimitReader(conn, payload_size))
					if err != nil {
						t.Errorf("failed reading: %s", err)
						return
					}
					_, err = io.Copy(conn, io.LimitReader(rand.Reader,
						payload_size))
					if err != nil {
						t.Errorf("failed writing: %s", err)
						return
					}
				}
				time.Sleep(sleep)
			}()
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		tcpClient, err := net.Dial(tcp_listener.Addr().Network(),
			tcp_listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		ssl_client, err := newClient(tcpClient)
		if err != nil {
			t.Error(err)
			return
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() {
				err = ssl_client.Close()
				if err != nil {
					t.Errorf("failed closing: %s", err)
				}
			}()
			for i := 0; i < loops; i++ {
				_, err := io.Copy(ssl_client, io.LimitReader(rand.Reader,
					payload_size))
				if err != nil {
					t.Errorf("failed writing: %s", err)
					return
				}
				_, err = io.Copy(io.Discard,
					io.LimitReader(ssl_client, payload_size))
				if err != nil {
					t.Errorf("failed reading: %s", err)
					return
				}
			}
			time.Sleep(sleep)
		}(i)
	}
	wg.Wait()
}

func TestStdlibLotsOfConns(t *testing.T) {
	tls_cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	tls_config := &tls.Config{
		Certificates:       []tls.Certificate{tls_cert},
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
	LotsOfConns(t, 1024*64, 10, 100, 0*time.Second,
		func(l net.Listener) net.Listener {
			return tls.NewListener(l, tls_config)
		}, func(c net.Conn) (net.Conn, error) {
			return tls.Client(c, tls_config), nil
		})
}

func TestOpenSSLLotsOfConns(t *testing.T) {
	ctx, err := NewCtx()
	if err != nil {
		t.Fatal(err)
	}
	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = ctx.UsePrivateKey(key); err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = ctx.UseCertificate(cert); err != nil {
		t.Fatal(err)
	}
	if err = ctx.SetCipherList("AES128-SHA"); err != nil {
		t.Fatal(err)
	}
	LotsOfConns(t, 1024*64, 10, 100, 0*time.Second,
		func(l net.Listener) net.Listener {
			return NewListener(l, ctx)
		}, func(c net.Conn) (net.Conn, error) {
			return Client(c, ctx)
		})
}
