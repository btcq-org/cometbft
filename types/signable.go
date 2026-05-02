package types

import (
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// MaxSignatureSize is a maximum allowed signature size for the Proposal
// and Vote.
// XXX: secp256k1 does not have max signature size defined.
var MaxSignatureSize = mldsa44.SignatureSize

// Signable is an interface for all signable things.
// It typically removes signatures before serializing.
// SignBytes returns the bytes to be signed
// NOTE: chainIDs are part of the SignBytes but not
// necessarily the object themselves.
// NOTE: Expected to panic if there is an error marshaling.
type Signable interface {
	SignBytes(chainID string) []byte
}
