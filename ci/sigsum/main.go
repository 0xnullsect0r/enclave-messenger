// Sigsum test vectors for crates/enclave-update (tests/sigsum/), made with
// the reference implementation (sigsum-go) so Enclave's verifier is checked
// against it, not against itself:
//
//	cd ci/sigsum && go run . > ../../crates/enclave-update/tests/sigsum/vectors.txt
//
// Keys come from fixed seeds; the proofs are what sigsum-submit writes.
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/types"
)

func signer(seed byte) *crypto.Ed25519Signer {
	var k crypto.PrivateKey
	for i := range k {
		k[i] = seed
	}
	return crypto.NewEd25519Signer(&k)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// One case: a log of `size` leaves, ours at `index`, cosigned at `time` by
// the witnesses given.
func emit(name string, size, index uint64, witnesses []*crypto.Ed25519Signer, time uint64) {
	log, submitter := signer(1), signer(2)
	logPub, subPub := log.Public(), submitter.Public()
	// What is logged: the SHA-256 of a release file's SHA-256.
	file := sha256.Sum256([]byte("enclave release " + name))
	msg := crypto.Hash(file)
	tree := merkle.NewTree()
	var ours types.Leaf
	for i := uint64(0); i < size; i++ {
		s := submitter
		m := crypto.HashBytes([]byte(fmt.Sprintf("other %s %d", name, i)))
		if i == index {
			m = msg
		}
		sig, err := types.SignLeafMessage(s, m[:])
		must(err)
		leaf := types.Leaf{Checksum: crypto.HashBytes(m[:]), Signature: sig, KeyHash: crypto.HashBytes(subPub[:])}
		if i == index {
			ours = leaf
		}
		h := leaf.ToHash()
		tree.AddLeafHash(&h)
	}
	th := types.TreeHead{Size: size, RootHash: tree.GetRootHash()}
	sth, err := th.Sign(log)
	must(err)
	cth := types.CosignedTreeHead{SignedTreeHead: sth, Cosignatures: map[crypto.Hash]types.Cosignature{}}
	origin := types.SigsumCheckpointOrigin(&logPub)
	for _, w := range witnesses {
		cs, err := th.Cosign(w, origin, time)
		must(err)
		wp := w.Public()
		cth.Cosignatures[crypto.HashBytes(wp[:])] = cs
	}
	p := proof.SigsumProof{LogKeyHash: crypto.HashBytes(logPub[:]), Leaf: proof.NewShortLeaf(&ours), TreeHead: cth}
	if size > 1 {
		path, err := tree.ProveInclusion(index, size)
		must(err)
		p.Inclusion = types.InclusionProof{LeafIndex: index, Path: path}
	}
	var buf bytes.Buffer
	must(p.ToASCII(&buf))
	// Check it with sigsum-go before writing it out: two of the three
	// witnesses (5, 6, 7) must have cosigned.
	var ws []crypto.PublicKey
	for _, s := range []byte{5, 6, 7} {
		ws = append(ws, signer(s).Public())
	}
	pol, err := policy.NewKofNPolicy([]crypto.PublicKey{logPub}, ws, 2)
	must(err)
	var back proof.SigsumProof
	must(back.FromASCII(bytes.NewReader(buf.Bytes())))
	verdict := "ok"
	if err := back.Verify(&msg, map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(subPub[:]): subPub}, pol); err != nil {
		verdict = "fail"
	}
	fmt.Printf("case %s %s\nmessage %x\nlog_key %x\nsubmit_key %x\n", name, verdict, msg[:], logPub[:], subPub[:])
	for _, s := range []byte{5, 6, 7} {
		wp := signer(s).Public()
		fmt.Printf("witness_key %x\n", wp[:])
	}
	fmt.Printf("proof\n%send\n", buf.String())
}

func main() {
	w := []*crypto.Ed25519Signer{signer(5), signer(6), signer(7)}
	emit("single", 1, 0, w[:2], 1_800_000_000)
	emit("seven", 7, 5, w, 1_800_000_100)
	emit("sixteen", 16, 0, w[1:], 1_800_000_200)
	emit("eleven-last", 11, 10, w[:2], 1_800_000_300)
	emit("one-witness", 9, 3, w[:1], 1_800_000_400)
}
