package mldsa

import (
	"bytes"
	gocrypto "crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"golang.org/x/crypto/ripemd160"
)

const (
	PrivKeyName = "tendermint/PrivKeyMLDSA"
	PubKeyName  = "tendermint/PubKeyMLDSA"

	KeyType = "mldsa44"
)

func init() {
	cmtjson.RegisterType(PubKey{}, PubKeyName)
	cmtjson.RegisterType(PrivKey{}, PrivKeyName)
}

type PrivKey []byte

func (privKey PrivKey) Bytes() []byte {
	return privKey
}

func (privKey PrivKey) PubKey() crypto.PubKey {
	scheme := mldsa44.Scheme()
	privateKey, err := scheme.UnmarshalBinaryPrivateKey(privKey)
	if err != nil {
		return nil
	}
	publicKey := privateKey.Public().(*mldsa44.PublicKey).Bytes()
	return PubKey(publicKey)
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherSecp, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherSecp[:]) == 1
	}
	return false
}

func (privKey PrivKey) Type() string {
	return KeyType
}

// GenPrivKey generates a new mldsa-44 private key
// It uses OS randomness to generate the private key.
func GenPrivKey() PrivKey {
	return genPrivKey()
}

// genPrivKey generates a new mldsa-44 private key using the provided reader.
func genPrivKey() PrivKey {
	scheme := mldsa44.Scheme()
	_, privateKey, err := scheme.GenerateKey()
	if err != nil {
		panic(err)
	}
	data, err := privateKey.MarshalBinary()
	if err != nil {
		panic(fmt.Errorf("failed to marshal private key: %w", err))
	}
	return PrivKey(data)
}

var one = new(big.Int).SetInt64(1)

func GenPrivKeyMLDSA44(secret []byte) PrivKey {
	secHash := sha256.Sum256(secret)
	scheme := mldsa44.Scheme()
	_, privateKey := scheme.DeriveKey(secHash[:])
	data, err := privateKey.MarshalBinary()
	if err != nil {
		panic(fmt.Errorf("failed to marshal private key: %w", err))
	}
	return PrivKey(data)
}

func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	scheme := mldsa44.Scheme()
	privateKey, err := scheme.UnmarshalBinaryPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	return privateKey.Sign(rand.Reader, msg, gocrypto.Hash(0))
}

//-------------------------------------

var _ crypto.PubKey = PubKey{}

type PubKey []byte

// Address returns a Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKey) Address() crypto.Address {
	// mldsa public key is quite large
	hasherSHA256 := sha256.New()
	_, _ = hasherSHA256.Write(pubKey) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	_, _ = hasherRIPEMD160.Write(sha) // does not error

	return crypto.Address(hasherRIPEMD160.Sum(nil))
}

// Bytes returns the pubkey marshaled with amino encoding.
func (pubKey PubKey) Bytes() []byte {
	return []byte(pubKey)
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyMLDSA{%X}", []byte(pubKey))
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if otherSecp, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	}
	return false
}

func (pubKey PubKey) Type() string {
	return KeyType
}

// VerifySignature verifies a signature of the form R || S.
// It rejects signatures which are not in lower-S form.
func (pubKey PubKey) VerifySignature(msg []byte, sigStr []byte) bool {
	if len(sigStr) != mldsa44.SignatureSize {
		return false
	}
	scheme := mldsa44.Scheme()
	publicKey, err := scheme.UnmarshalBinaryPublicKey(pubKey)
	if err != nil {
		return false
	}
	return scheme.Verify(publicKey, msg, sigStr, nil)
}
