package kscrypto

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"testing"
)

type blockCipherTestParams struct {
	name          string
	ptbufLengths  []int
	ctbufLengths  []int
	alg           BlockCipherAlg
	pad           BlockCipherPadding
	finalInUpdate bool // combine final with update
}

func TestGoCryptoBlockCipherEncryptionCtx(t *testing.T) {

	tvs := []blockCipherTestParams{
		{
			name:         "blk-test-0",
			ptbufLengths: []int{32, 16},
			ctbufLengths: []int{32, 16},
			alg:          AES_256_CBC, pad: NO_CRYPTO_PADDING, finalInUpdate: false,
		},
		{
			name:         "blk-test-1",
			ptbufLengths: []int{16},
			ctbufLengths: []int{32},
			alg:          AES_192_CBC, pad: PKCS7_CRYPTO_PADDING, finalInUpdate: false,
		},
		{
			name:         "blk-test-2",
			ptbufLengths: []int{32, 16},
			ctbufLengths: []int{32, 16},
			alg:          AES_256_CBC, pad: NO_CRYPTO_PADDING, finalInUpdate: true,
		},
		{
			name:         "blk-test-3",
			ptbufLengths: []int{13, 18},
			ctbufLengths: []int{16, 16},
			alg:          AES_128_CBC, pad: PKCS7_CRYPTO_PADDING, finalInUpdate: false,
		},
		{
			name:         "blk-test-4",
			ptbufLengths: []int{13, 3},
			ctbufLengths: []int{32},
			alg:          AES_256_ECB, pad: PKCS7_CRYPTO_PADDING, finalInUpdate: false,
		},

		{
			name:         "blk-test-5",
			ptbufLengths: []int{13, 3},
			ctbufLengths: []int{17, 15},
			alg:          AES_192_ECB, pad: PKCS7_CRYPTO_PADDING, finalInUpdate: false,
		},
		{
			name:         "blk-test-6",
			ptbufLengths: []int{33, 15},
			ctbufLengths: []int{34, 14},
			alg:          AES_192_ECB, pad: NO_CRYPTO_PADDING, finalInUpdate: false,
		},
		{
			name:         "blk-test-7",
			ptbufLengths: []int{31, 15},
			ctbufLengths: []int{34, 14},
			alg:          TDES_CBC, pad: PKCS7_CRYPTO_PADDING, finalInUpdate: false,
		},
	}

	for tn := 0; tn < len(tvs); tn++ {

		tv := &tvs[tn]
		t.Run(tv.name, func(t *testing.T) {

			var key, iv []byte
			keyLen, ivLen := GetKeyAndIVSize(tv.alg)
			key = make([]byte, keyLen/8)
			_, err := rand.Read(key)
			require.NoError(t, err)

			if ivLen > 0 {
				iv = make([]byte, ivLen)
				_, err = rand.Read(iv)
				require.NoError(t, err)
			}

			enc := NewGoCryptoBlockCipherEncryptor()
			require.NotNil(t, enc)
			err = enc.Init(tv.alg, tv.pad, key, iv)
			require.NoError(t, err)

			dec := NewGoCryptoBlockCipherDecryptor()
			require.NotNil(t, dec)
			err = dec.Init(tv.alg, tv.pad, key, iv)
			require.NoError(t, err)

			var pt, ct []byte

			var ptlen, ctlen int
			for i := 0; i < len(tv.ptbufLengths); i++ {
				ptlen += tv.ptbufLengths[i]
			}
			for i := 0; i < len(tv.ctbufLengths); i++ {
				ctlen += tv.ctbufLengths[i]
			}
			pt = make([]byte, ptlen)
			pt1 := make([]byte, ptlen)
			_, err = rand.Read(pt)
			copy(pt1, pt)
			require.NoError(t, err)

			t.Logf("pt: %x", pt)

			var si, ei int
			// encrypt
			si = 0
			ei = 0
			for i := 0; i < len(tv.ptbufLengths); i++ {
				ei += tv.ptbufLengths[i]
				final := false
				if i == len(tv.ptbufLengths)-1 {
					final = tv.finalInUpdate
				}
				obuf, err := enc.Update(pt[si:ei], final)
				si = ei
				require.NoError(t, err)
				ct = append(ct, obuf...)
			}

			if !tv.finalInUpdate {
				obuf, err := enc.Final()
				require.NoError(t, err)
				t.Log("ct final", ct)
				ct = append(ct, obuf...)
			}
			t.Logf("ct: %x", ct)
			require.Equal(t, ctlen, len(ct))

			si = 0
			ei = 0
			var dt []byte
			for i := 0; i < len(tv.ctbufLengths); i++ {
				ei += tv.ctbufLengths[i]
				final := false
				if i == len(tv.ctbufLengths)-1 {
					final = tv.finalInUpdate
				}
				obuf, err := dec.Update(ct[si:ei], final)
				si = ei
				require.NoError(t, err)
				dt = append(dt, obuf...)
			}

			if !tv.finalInUpdate {
				obuf, err := dec.Final()
				require.NoError(t, err)
				dt = append(dt, obuf...)
			}
			t.Logf("dt: %x", dt)
			t.Logf("pt1 %x", pt1)
			t.Logf("pt %x", pt)
			require.EqualValues(t, pt1, dt)
		})
	}
}

func TestGoCryptoAESBlockCipherNoPaddingBadLength(t *testing.T) {
	// test encrypting with a data buffer that is not a multiple of block size
	enc := NewGoCryptoBlockCipherEncryptor()
	require.NotNil(t, enc)
	keySize := 256

	key := make([]byte, keySize/8)
	_, err := rand.Read(key)
	require.NoError(t, err)

	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	err = enc.Init(AES_256_CBC, NO_CRYPTO_PADDING, key, iv)
	require.NoError(t, err)

	ptLen := 33
	pt := make([]byte, ptLen)
	_, err = rand.Read(pt)
	pt1 := make([]byte, ptLen)
	require.NoError(t, err)
	copy(pt1, pt)
	t.Logf("pt  is : %x", pt)

	ct, err := enc.Update(pt, false)
	require.NoError(t, err)
	require.NotNil(t, ct)

	_, err = enc.Final()
	require.Error(t, err)

	t.Logf("pt is %x", pt)
	t.Logf("pt1 is %x", pt1)

	// test decrypting with a data buffer that is not a multiple of block size
	dec := NewGoCryptoBlockCipherDecryptor()
	require.NotNil(t, dec)

	err = dec.Init(AES_256_CBC, NO_CRYPTO_PADDING, key, iv)
	require.NoError(t, err)

	dt, err := dec.Update(pt1, false)
	require.NoError(t, err)
	require.NotNil(t, dt)

	_, err = dec.Final()
	require.Error(t, err)
}

func TestGoCryptoBlockCipherVectorsEncrypt(t *testing.T) {
	vectors := []struct {
		key string
		iv  string
		in  string
		out string
		alg BlockCipherAlg
	}{
		{
			key: "c286696d887c9aa0611bbb3e2025a45a", iv: "562e17996d093d28ddb3ba695a2e6f58",
			in:  `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`,
			out: `d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1`,
			alg: AES_256_CBC,
		},
		{
			key: "6c3ea0477630ce21a2ce334aa746c2cd", iv: "c782dc4c098c66cbd9cd27d825682c81",
			in:  `5468697320697320612034382d62797465206d657373616765202865786163746c7920332041455320626c6f636b7329`,
			out: `d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5021c19216bad525c8579695d83ba2684`,
			alg: AES_256_CBC,
		},
		{
			key: "56e47a38c5598974bc46903dba290349", iv: "8ce82eefbea0da3c44699ed7db51b7d9",
			in:  `a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf`,
			out: `c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55`,
			alg: AES_256_CBC,
		},
		{
			key: "2b7e151628aed2a6abf7158809cf4f3c", iv: "",
			in:  `6bc1bee22e409f96e93d7e117393172a`,
			out: `3ad77bb40d7a3660a89ecaf32466ef97`,
			alg: AES_128_ECB,
		},
		{
			key: "2b7e151628aed2a6abf7158809cf4f3c", iv: "",
			in:  `ae2d8a571e03ac9c9eb76fac45af8e51`,
			out: `f5d3d58503b9699de785895a96fdbaaf`,
			alg: AES_128_ECB,
		},
		{
			key: "2b7e151628aed2a6abf7158809cf4f3c", iv: "",
			in:  `30c81c46a35ce411e5fbc1191a0a52ef`,
			out: `43b1cd7f598ece23881b00e3ed030688`,
			alg: AES_128_ECB,
		},
		{
			key: "2b7e151628aed2a6abf7158809cf4f3c", iv: "",
			in:  `f69f2445df4f9b17ad2b417be66c3710`,
			out: `7b0c785e27e8ad3f8223207104725dd4`,
			alg: AES_128_ECB,
		},
		{
			key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", iv: "",
			in:  `6bc1bee22e409f96e93d7e117393172a`,
			out: `bd334f1d6e45f25ff712a214571fa5cc`,
			alg: AES_192_ECB,
		},
		{
			key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", iv: "",
			in:  `ae2d8a571e03ac9c9eb76fac45af8e51`,
			out: `974104846d0ad3ad7734ecb3ecee4eef`,
			alg: AES_192_ECB,
		},
		{
			key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", iv: "",
			in:  `30c81c46a35ce411e5fbc1191a0a52ef`,
			out: `ef7afd2270e2e60adce0ba2face6444e`,
			alg: AES_192_ECB,
		},
		{
			key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", iv: "",
			in:  `f69f2445df4f9b17ad2b417be66c3710`,
			out: `9a4b41ba738d6c72fb16691603c18e0e`,
			alg: AES_192_ECB,
		},
		{
			key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", iv: "",
			in:  `6bc1bee22e409f96e93d7e117393172a`,
			out: `f3eed1bdb5d2a03c064b5a7e3db181f8`,
			alg: AES_256_ECB,
		},
		{
			key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", iv: "",
			in:  `ae2d8a571e03ac9c9eb76fac45af8e51`,
			out: `591ccb10d410ed26dc5ba74a31362870`,
			alg: AES_192_ECB,
		},
		{
			key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", iv: "",
			in:  `30c81c46a35ce411e5fbc1191a0a52ef`,
			out: `b6ed21b99ca6f4f9f153e7b1beafed1d`,
			alg: AES_192_ECB,
		},
		{
			key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", iv: "",
			in:  `f69f2445df4f9b17ad2b417be66c3710`,
			out: `23304b7a39f9f3ff067d8d8f9e24ecc7`,
			alg: AES_192_ECB,
		},
	}

	for _, in := range vectors {
		t.Run("", func(t *testing.T) {
			aes := NewGoCryptoBlockCipherEncryptor()
			k, _ := hex.DecodeString(in.key)
			iv := []byte(nil)
			if in.iv != "" {
				iv, _ = hex.DecodeString(in.iv)
			}
			indata, _ := hex.DecodeString(in.in)
			e := aes.Init(in.alg, NO_CRYPTO_PADDING, k, iv)
			if e != nil {
				t.Fatal(e.Error())
			}
			o, e := aes.Update(indata, true)
			if e != nil {
				t.Fatal(e.Error())
			}
			t.Log(hex.EncodeToString(o))
			if hex.EncodeToString(o) != in.out {
				t.Fatal("Mismatch", hex.EncodeToString(o), "=====", in.out)
			}
		})
	}

}

func TestGoCryptoBlockCipherVectorsDecrypt255(t *testing.T) {
	vectors := []struct {
		key  string
		iv   string
		in   string
		out  string
		out1 string
		alg  BlockCipherAlg
	}{
		{
			key: "00112233445567880011223344556788", iv: "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
			in:  `b423b5445d374bd8932c492196f8c47a`,
			out: `1111111122222222`,
			alg: AES_128_CBC,
		},
	}

	for _, in := range vectors {
		t.Run("", func(t *testing.T) {
			ar := NewGoCryptoBlockCipherDecryptor()
			k, _ := hex.DecodeString(in.key)
			iv := []byte(nil)
			if in.iv != "" {
				iv, _ = hex.DecodeString(in.iv)
			}
			indata, _ := hex.DecodeString(in.out)

			e := ar.Init(in.alg, NO_CRYPTO_PADDING, k, iv)

			if e != nil {
				t.Fatal(e.Error())
			}

			o, e := ar.Update(indata, false)
			if e != nil {
				t.Fatal(e.Error())
			}
			require.Nil(t, o)

			o, e = ar.Update(indata, false)
			if e != nil {
				t.Fatal(e.Error())
			}
			require.NotNil(t, o)
			require.Equal(t, hex.EncodeToString(o), in.in)

		})
	}
}
