package tlcp

import "testing"

func TestSM2SignatureCodeCompatibilityDoesNotChangeCipherChoice(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		config := (&Config{EnableRFC8998SM2Code: enabled, CipherSuites: []uint16{ECC_SM4_GCM_SM3}}).Clone()
		if config.EnableRFC8998SM2Code != enabled {
			t.Fatal("compatibility flag lost on clone")
		}
		hello, err := Client(nil, config).makeClientHello()
		if err != nil {
			t.Fatal(err)
		}
		count := 1
		if enabled {
			count = 2
		}
		if len(hello.supportedSignatureAlgorithms) != count || hello.supportedSignatureAlgorithms[0] != SM2WithSM3 {
			t.Fatal("standard SM2 code changed")
		}
		if enabled && hello.supportedSignatureAlgorithms[1] != SignatureScheme(0x0708) {
			t.Fatal("missing interoperability code")
		}
		if len(hello.cipherSuites) != 1 || hello.cipherSuites[0] != ECC_SM4_GCM_SM3 {
			t.Fatal("compatibility enabled a different cipher")
		}
	}
}
