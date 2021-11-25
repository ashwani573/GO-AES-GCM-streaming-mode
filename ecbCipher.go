package kscrypto

import (
	"crypto/cipher"
)

type ecbStruct struct {
	block     cipher.Block
	blockSize int
	temp      []byte
}

func newECBObject(blk cipher.Block) *ecbStruct {
	return &ecbStruct{
		block:     blk,
		blockSize: blk.BlockSize(),
		temp:      make([]byte, blk.BlockSize()),
	}
}

type ecbEncryptionCtx ecbStruct

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncryptionCtx)(newECBObject(b))
}

func (ec *ecbEncryptionCtx) BlockSize() int { return ec.blockSize }

func (ec *ecbEncryptionCtx) CryptBlocks(destination, source []byte) {

	if len(source)%ec.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}

	if len(destination) < len(source) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(source) > 0 {
		ec.block.Encrypt(destination[:ec.blockSize], source[:ec.blockSize])
		source = source[ec.blockSize:]
		destination = destination[ec.blockSize:]
	}
}

type ecbDecryptionCtx ecbStruct

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecryptionCtx)(newECBObject(b))
}

func (dc *ecbDecryptionCtx) BlockSize() int { return dc.blockSize }

func (dc *ecbDecryptionCtx) CryptBlocks(destination, source []byte) {
	if len(source)%dc.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(destination) < len(source) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(source) == 0 {
		return
	}

	for len(source) > 0 {
		dc.block.Decrypt(destination[:dc.blockSize], source[:dc.blockSize])
		source = source[dc.blockSize:]
		destination = destination[dc.blockSize:]
	}

}
