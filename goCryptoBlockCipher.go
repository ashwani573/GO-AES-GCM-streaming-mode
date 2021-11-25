package kscrypto

import (
	goaes "crypto/aes"
	"crypto/cipher"
	godes "crypto/des" // #nosec: G401,G502
	"errors"
)


type BlockCipherAlg string

const (
	AES_256_CBC  BlockCipherAlg = "aes-256-cbc"
	AES_192_CBC  BlockCipherAlg = "aes-192-cbc"
	AES_128_CBC  BlockCipherAlg = "aes-128-cbc"
	AES_256_ECB  BlockCipherAlg = "aes-256-ecb"
	AES_192_ECB  BlockCipherAlg = "aes-192-ecb"
	AES_128_ECB  BlockCipherAlg = "aes-128-ecb"
	TDES_CBC     BlockCipherAlg = "des-ede3-cbc"
	TDES_112_CBC BlockCipherAlg = "des-ede-cbc"
	TDES_192_ECB BlockCipherAlg = "des-ede3"
	TDES_128_ECB BlockCipherAlg = "des-ede"
)

type BlockCipherPadding string

const (
	PKCS7_CRYPTO_PADDING BlockCipherPadding = "pkcs7"
	NO_CRYPTO_PADDING    BlockCipherPadding = "none"
)

func GetKeyAndIVSize(alg BlockCipherAlg) (int, int) {
	switch alg {
	case AES_256_CBC:
		return 256, 16
	case AES_256_ECB:
		return 256, 0
	case AES_192_CBC:
		return 192, 16
	case AES_192_ECB:
		return 192, 0
	case AES_128_CBC:
		return 128, 16
	case AES_128_ECB:
		return 128, 0
	case TDES_CBC:
		return 192, 8
	case TDES_192_ECB:
		return 192, 0
	case TDES_128_ECB:
		return 128, 0
	default:
		return 0, 0
	}
}


const AES_BLOCK_SIZE = 16     //nolint:golint,stylecheck
const TDES_BLOCK_SIZE = 8     //nolint:golint,stylecheck
const DOUBLE_DES_KEY_LEN = 16 //nolint:golint,stylecheck

const (
	blockCipherAlgTDES = "TDES"
	blockCipherAlgAES  = "AES"
	blockCipherModeCBC = "CBC"
	blockCipherModeECB = "ECB"
)

/*Function will take algorithm as input and
  Return algo and mode in return*/
func GetAlgoAndMode(alg BlockCipherAlg) (string, string) {
	switch alg {
	case AES_256_CBC, AES_192_CBC, AES_128_CBC:
		return blockCipherAlgAES, blockCipherModeCBC
	case AES_256_ECB, AES_192_ECB, AES_128_ECB:
		return blockCipherAlgAES, blockCipherModeECB
	case TDES_CBC, TDES_112_CBC:
		return blockCipherAlgTDES, blockCipherModeCBC
	case TDES_192_ECB, TDES_128_ECB:
		return blockCipherAlgTDES, blockCipherModeECB
	default:
		return "", ""
	}
}

type GoCryptoBlockCipherEncryptor interface {
	Init(alg BlockCipherAlg, pad BlockCipherPadding, key, iv []byte) error
	Update(pt []byte, final bool) ([]byte, error)
	Final() ([]byte, error)
}

type GoCryptoBlockCipherDecryptor interface {
	Init(alg BlockCipherAlg, pad BlockCipherPadding, key, iv []byte) error
	Update(ct []byte, final bool) ([]byte, error)
	Final() ([]byte, error)
}

/* To provide Keying Oprion 2 for TDES, that is to support 128bits / 16bytes key*/
func keyingOption2(key []byte) []byte {
	var twentyFourByteKey []byte
	twentyFourByteKey = append(twentyFourByteKey, key[:16]...)
	twentyFourByteKey = append(twentyFourByteKey, key[:8]...)
	return twentyFourByteKey
}

/*Encryption context*/
type GoCryptoBlockCipherEncryptionCtx struct {
	blockSize    int
	iv           []byte
	dataRemained []byte
	padding      BlockCipherPadding
	blockMode    cipher.BlockMode
	block        cipher.Block
}

func NewGoCryptoBlockCipherEncryptor() *GoCryptoBlockCipherEncryptionCtx {
	ec := &GoCryptoBlockCipherEncryptionCtx{}
	return ec
}

/*Encryption context initialization*/
func (ec *GoCryptoBlockCipherEncryptionCtx) Init(alg BlockCipherAlg, pad BlockCipherPadding, key, iv []byte) error {

	var err error
	ec.dataRemained = make([]byte, 0)
	algo, mode := GetAlgoAndMode(alg)
	if mode == "" {
		return errors.New("Invalid block cipher algorithm")
	}

	if len(key) == 0 || func() bool {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return true
		}
		return false
	}() {
		return errors.New("Invalid key and/or IV")
	}
	// TODO: Check if wrong key is not getting selected
	ec.padding = pad

	switch algo { //nolint:dupl
	case blockCipherAlgAES:
		if mode == blockCipherModeECB {
			if len(iv) != 0 {
				return errors.New("ECB Mode must not have IV")
			}
		} else if mode == blockCipherModeCBC {
			if len(iv) == 0 { //nolint:gocritic
				//default iv handling
				ec.iv = make([]byte, AES_BLOCK_SIZE)
			} else if len(iv) == AES_BLOCK_SIZE {
				ec.iv = make([]byte, AES_BLOCK_SIZE)
				copy(ec.iv, iv)
			} else {
				return errors.New("AES CBC mode requires a 16 byte IV")
			}
		}

		ec.block, err = goaes.NewCipher(key)
		if err != nil {
			return errors.New("invalid key provided")
		}

	case blockCipherAlgTDES:
		if mode == blockCipherModeECB {
			if len(iv) != 0 {
				return errors.New("ECB Mode must not have IV")
			}
		} else if mode == blockCipherModeCBC {
			if len(iv) == 0 { //nolint:gocritic
				//default case handling
				ec.iv = make([]byte, TDES_BLOCK_SIZE)
			} else if len(iv) == TDES_BLOCK_SIZE {
				ec.iv = make([]byte, TDES_BLOCK_SIZE)
				copy(ec.iv, iv)
			} else {
				return errors.New("TDES CBC mode requires a 8 byte IV")
			}
		}

		if len(key) == DOUBLE_DES_KEY_LEN {
			twentyFourByteKey := keyingOption2(key)
			key = twentyFourByteKey
		}
		ec.block, err = godes.NewTripleDESCipher(key) // #nosec: G401
		if err != nil {
			return errors.New("invalid key provided")
		}
	}

	if mode == blockCipherModeCBC { //nolint:gocritic
		ec.blockMode = cipher.NewCBCEncrypter(ec.block, ec.iv)
	} else if mode == blockCipherModeECB {
		ec.blockMode = NewECBEncrypter(ec.block)
	} else {
		return errors.New("invalid mode provided")
	}
	ec.blockSize = ec.blockMode.BlockSize()
	return nil
}

/*Update routine for encrytion*/
func (ec *GoCryptoBlockCipherEncryptionCtx) Update(pt []byte, final bool) ([]byte, error) {
	if ec.blockMode == nil {
		return nil, errors.New("Crypto context not initialized")
	}
	ct := make([]byte, len(pt))
	copy(ct, pt)
	if len(ec.dataRemained) > 0 {
		ct = append(ec.dataRemained, pt...) //nolint:gocritic
		ec.dataRemained = ec.dataRemained[len(ec.dataRemained):]
	}
	remainData := (len(ct)) % (ec.blockSize)
	if remainData != 0 {
		if len(ct) > ec.blockSize {
			remainData = (len(ct)) - remainData
			ct, ec.dataRemained = ct[:remainData], ct[remainData:]
			ec.blockMode.CryptBlocks(ct, ct)
		} else {
			ec.dataRemained = ct
			if !final {
				return nil, nil
			}
			ct = ct[len(ct):]
		}
	} else {
		ec.blockMode.CryptBlocks(ct, ct)
	}

	if final {
		buf, err := ec.Final()
		if err != nil {
			return nil, errors.New(err.Error())
		}
		ct = append(ct, buf...)
	}
	return ct, nil
}

/*Final routine for encrytion*/
func (ec *GoCryptoBlockCipherEncryptionCtx) Final() ([]byte, error) {
	if ec.blockMode == nil {
		return nil, errors.New("Crypto context not initialized")
	}
	var ct []byte
	if ec.padding != NO_CRYPTO_PADDING {
		ct = make([]byte, ec.blockSize)
		d := ec.dataRemained
		ptLen := len(d)

		for i := len(d); i < ec.blockSize; i++ {
			d = append(d, byte(ec.blockSize-ptLen))
		}
		ec.blockMode.CryptBlocks(ct, d[:ec.blockSize])
	}

	if ec.padding == NO_CRYPTO_PADDING && len(ec.dataRemained) != 0 {
		return nil, errors.New("Invalid data length")
	}
	ec.blockMode = nil
	return ct, nil
}

type GoCryptoBlockCipherDecryptionCtx struct {
	iv           []byte
	dataRemained []byte
	padding      BlockCipherPadding
	blockMode    cipher.BlockMode
	blockSize    int
	block        cipher.Block
}

func NewGoCryptoBlockCipherDecryptor() *GoCryptoBlockCipherDecryptionCtx {
	dc := &GoCryptoBlockCipherDecryptionCtx{}
	return dc
}

/*Initialization routine for decrytion*/
func (dc *GoCryptoBlockCipherDecryptionCtx) Init(alg BlockCipherAlg, pad BlockCipherPadding, key, iv []byte) error {

	var err error
	dc.dataRemained = make([]byte, 0)
	algo, dcMode := GetAlgoAndMode(alg)
	if dcMode == "" {
		return errors.New("Invalid algorithm")
	}

	if len(key) == 0 || func() bool {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return true
		}
		return false
	}() {
		return errors.New("Invalid Key")
	}

	// TODO: Check if wrong key is not getting selected
	dc.padding = pad

	switch algo { //nolint:dupl
	case blockCipherAlgAES:
		if dcMode == blockCipherModeECB {
			if len(iv) != 0 {
				return errors.New("ECB Mode must not have IV")
			}
		} else if dcMode == blockCipherModeCBC {
			if len(iv) == 0 { //nolint:gocritic
				//default case handling
				dc.iv = make([]byte, AES_BLOCK_SIZE)
			} else if len(iv) == AES_BLOCK_SIZE {
				dc.iv = make([]byte, AES_BLOCK_SIZE)
				copy(dc.iv, iv)
			} else {
				return errors.New("AES CBC mode requires a 16 byte IV")
			}
		}
		dc.block, err = goaes.NewCipher(key)
		if err != nil {
			return errors.New("invalid key provided")
		}

	case blockCipherAlgTDES:
		if dcMode == blockCipherModeECB {
			if len(iv) != 0 {
				return errors.New("ECB Mode must not have IV")
			}
		} else if dcMode == blockCipherModeCBC {
			if len(iv) == 0 { //nolint:gocritic
				//default case handling
				dc.iv = make([]byte, TDES_BLOCK_SIZE)
			} else if len(iv) == TDES_BLOCK_SIZE {
				dc.iv = make([]byte, TDES_BLOCK_SIZE)
				copy(dc.iv, iv)
			} else {
				return errors.New("TDES CBC mode requires a 8 byte IV")
			}
		}

		if len(key) == DOUBLE_DES_KEY_LEN {
			twentyFourByteKey := keyingOption2(key)
			key = twentyFourByteKey
		}
		dc.block, err = godes.NewTripleDESCipher(key) // #nosec: G401
		if err != nil {
			return errors.New("invalid key provided")
		}
	}

	if dcMode == blockCipherModeCBC { //nolint:gocritic
		dc.blockMode = cipher.NewCBCDecrypter(dc.block, dc.iv)
	} else if dcMode == blockCipherModeECB {
		dc.blockMode = NewECBDecrypter(dc.block)
	} else {
		return errors.New("invalid mode provided")
	}
	dc.blockSize = dc.blockMode.BlockSize()
	return nil
}

/*Update routine for decrytion*/
func (dc *GoCryptoBlockCipherDecryptionCtx) Update(ct []byte, final bool) ([]byte, error) {
	if dc.blockMode == nil {
		return nil, errors.New("Crypto context not initialized")
	}
	pt := make([]byte, len(ct))
	copy(pt, ct)

	if len(dc.dataRemained) > 0 {
		pt = append(dc.dataRemained, pt...)
		dc.dataRemained = dc.dataRemained[len(dc.dataRemained):]
	}
	remainData := (len(pt)) % (dc.blockSize)
	if remainData != 0 { //nolint:gocritic
		if len(pt) > dc.blockSize {
			remainData = (len(pt)) - remainData
			pt, dc.dataRemained = pt[:remainData], pt[remainData:]
			dc.blockMode.CryptBlocks(pt, pt)
		} else {
			dc.dataRemained = pt
			if !final {
				return nil, nil
			}
		}
	} else if dc.padding == PKCS7_CRYPTO_PADDING && len(pt) >= dc.blockSize {
		pt, dc.dataRemained = pt[:len(pt)-dc.blockSize], pt[len(pt)-dc.blockSize:]
		if len(pt) == 0 {
			if !final {
				return nil, nil
			}
		} else {
			dc.blockMode.CryptBlocks(pt, pt)
		}
	} else {
		dc.blockMode.CryptBlocks(pt, pt)
	}
	if final {
		tmpPt, err := dc.Final()
		if err != nil {
			return nil, errors.New(err.Error())
		}
		pt = append(pt, tmpPt...)
	}
	return pt, nil
}

/*Final routine for decrytion*/
func (dc *GoCryptoBlockCipherDecryptionCtx) Final() ([]byte, error) {

	pt := make([]byte, 0)
	if dc.blockMode == nil {
		return nil, errors.New("Crypto context not initialized")
	}
	if len(dc.dataRemained) == 0 {
		return pt, nil
	}
	if len(dc.dataRemained)%dc.blockSize != 0 {
		return nil, errors.New("Invalid data length")
	}

	if len(dc.dataRemained) > 0 {
		d := dc.dataRemained
		buf := make([]byte, dc.blockSize)
		dc.blockMode.CryptBlocks(buf, d[:dc.blockSize])

		pt = append(pt, buf...)
	}

	if dc.padding != NO_CRYPTO_PADDING {
		pad := int(pt[len(pt)-1])
		if pad > dc.blockSize || pad < 0 {
			return nil, errors.New("Invalid padding")
		}
		pt = pt[:len(pt)-pad]
	} else if len(dc.dataRemained) != dc.blockSize {
		return nil, errors.New("Invalid data length")
	}
	dc.blockMode = nil
	return pt, nil
}
