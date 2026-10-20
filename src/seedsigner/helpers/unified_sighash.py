"""
The unified opt-in signature hash of the Bitcoin BLAKE2b chain (XBT).

A signature whose hash type has the 0x20 bit set (SIGHASH_UNIFIED) is checked
against a different message than BIP143's: Bitcoin Knots BLAKE2b,
doc/unified-sighash.md and SignatureHashUnified() in src/script/interpreter.cpp.
SeedSigner signs with it only when the PSBT asks for it in PSBT_IN_SIGHASH_TYPE
(0x21 = SIGHASH_UNIFIED | SIGHASH_ALL). Two things follow from that message:

* Replay protection. A node that does not know the bit computes the legacy
  message for the same byte, so the signature does not verify on the SHA-256
  chain the coins share their history with.
* No CVE-2020-14199. Like BIP341, the message commits to the amount and the
  scriptPubKey of EVERY input, not only the one being signed. A coordinator that
  lies about an input amount gets a signature that is invalid on chain, so the
  fee the device shows is the fee that can be paid.

Only bare/P2SH-wrapped and segwit v0 inputs are built here (script types 0 and
1); taproot (2 and 3) also commits to the annex and the tapleaf, which SeedSigner
does not sign under this hash type.
"""
import hashlib
from typing import List, Sequence, Tuple

from embit import compact, hashes, script
from embit.psbt import PSBT


SIGHASH_ALL = 0x01
SIGHASH_UNIFIED = 0x20
SIGHASH_UNIFIED_ALL = SIGHASH_UNIFIED | SIGHASH_ALL  # 0x21

SCRIPT_TYPE_BASE = 0
SCRIPT_TYPE_SEGWIT_V0 = 1


class UnifiedSighashError(Exception):
    pass


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    t = _sha256(tag.encode())
    return _sha256(t + t + msg)


def _ser_string(b: bytes) -> bytes:
    return compact.to_bytes(len(b)) + b


def unified_message_hash(
    *,
    version: int,
    locktime: int,
    hash_type: int,
    script_type: int,
    prevouts: Sequence[bytes],
    amounts: Sequence[int],
    spent_scripts: Sequence[bytes],
    sequences: Sequence[int],
    outputs: Sequence[Tuple[int, bytes]],
    input_index: int,
    script_code: bytes,
) -> bytes:
    """The 32-byte unified sighash, laid out as SignatureHashUnified() writes it.

    `prevouts` are 36-byte outpoints (txid little-endian + vout), `spent_scripts`
    the raw scriptPubKeys, `outputs` (value, raw scriptPubKey) pairs and
    `script_code` the BIP143 scriptCode without its length prefix.
    """
    n = len(prevouts)
    if not (len(amounts) == len(spent_scripts) == len(sequences) == n):
        raise UnifiedSighashError("The unified sighash needs every input's amount and script")
    if not 0 <= input_index < n:
        raise UnifiedSighashError("Input index out of range")
    if script_type not in (SCRIPT_TYPE_BASE, SCRIPT_TYPE_SEGWIT_V0):
        raise UnifiedSighashError("Unsupported script type %d" % script_type)
    if not hash_type & SIGHASH_UNIFIED:
        raise UnifiedSighashError("Hash type 0x%02x did not opt in to the unified sighash" % hash_type)

    anyone_can_pay = bool(hash_type & 0x80)
    output_type = hash_type & 0x1F

    msg = bytearray()
    msg += b"\x00"                                         # epoch
    msg += bytes([hash_type & 0xFF])
    msg += (version & 0xFFFFFFFF).to_bytes(4, "little")
    msg += (locktime & 0xFFFFFFFF).to_bytes(4, "little") + b"\x00"   # five bytes
    if not anyone_can_pay:
        msg += _sha256(b"".join(prevouts))
        msg += _sha256(b"".join(int(a).to_bytes(8, "little") for a in amounts))
        msg += _sha256(b"".join(_ser_string(s) for s in spent_scripts))
        msg += _sha256(b"".join((q & 0xFFFFFFFF).to_bytes(4, "little") for q in sequences))
    if output_type not in (0x02, 0x03):
        msg += _sha256(b"".join(int(v).to_bytes(8, "little") + _ser_string(s) for v, s in outputs))
    msg += bytes([script_type])
    if anyone_can_pay:
        msg += prevouts[input_index]
        msg += int(amounts[input_index]).to_bytes(8, "little") + _ser_string(spent_scripts[input_index])
        msg += (sequences[input_index] & 0xFFFFFFFF).to_bytes(4, "little")
    else:
        msg += input_index.to_bytes(4, "little")
    msg += _ser_string(script_code)
    if output_type == 0x03:
        if input_index >= len(outputs):
            raise UnifiedSighashError("SIGHASH_SINGLE has no output at the input's index")
        v, s = outputs[input_index]
        msg += _sha256(int(v).to_bytes(8, "little") + _ser_string(s))
    return _tagged_hash("UnifiedSighash", bytes(msg))


def spent_outputs(psbt: PSBT) -> List[Tuple[int, bytes]]:
    """(amount, scriptPubKey) of every input, which the unified message commits to."""
    out = []
    for i, inp in enumerate(psbt.inputs):
        utxo = inp.utxo
        if utxo is None:
            raise UnifiedSighashError("Input %d has no previous output: cannot sign with the unified sighash" % (i + 1))
        out.append((utxo.value, utxo.script_pubkey.data))
    return out


def script_code_for(psbt: PSBT, i: int) -> bytes:
    """BIP143 scriptCode of segwit v0 input `i` (P2WPKH, P2SH-P2WPKH or P2WSH)."""
    inp = psbt.inputs[i]
    spk = inp.utxo.script_pubkey
    kind = spk.script_type()
    if kind == "p2sh" and inp.redeem_script is not None:
        if script.p2sh(inp.redeem_script).data != spk.data:
            raise UnifiedSighashError("Input %d: redeem script does not match its address" % (i + 1))
        spk = inp.redeem_script
        kind = spk.script_type()
    if kind == "p2wpkh":
        return script.p2pkh_from_p2wpkh(spk).data
    if kind == "p2wsh":
        if inp.witness_script is None or script.p2wsh(inp.witness_script).data != spk.data:
            raise UnifiedSighashError("Input %d: witness script does not match its address" % (i + 1))
        return inp.witness_script.data
    raise UnifiedSighashError("Input %d: the unified sighash is only signed for segwit v0 inputs here" % (i + 1))


def psbt_unified_sighash(psbt: PSBT, i: int, hash_type: int = SIGHASH_UNIFIED_ALL) -> bytes:
    """The unified sighash of segwit v0 input `i` of `psbt`."""
    tx = psbt.tx
    return unified_message_hash(
        version=tx.version,
        locktime=tx.locktime,
        hash_type=hash_type,
        script_type=SCRIPT_TYPE_SEGWIT_V0,
        prevouts=[bytes(reversed(vin.txid)) + vin.vout.to_bytes(4, "little") for vin in tx.vin],
        amounts=[v for v, _ in spent_outputs(psbt)],
        spent_scripts=[s for _, s in spent_outputs(psbt)],
        sequences=[vin.sequence for vin in tx.vin],
        outputs=[(vout.value, vout.script_pubkey.data) for vout in tx.vout],
        input_index=i,
        script_code=script_code_for(psbt, i),
    )


def sign_unified(psbt: PSBT, root) -> int:
    """Sign every input that asks for 0x21 with the keys of `root` (an HDKey).

    embit's own sign_with() skips these inputs (it only signs the hash type it
    was asked for), so this runs after it. Returns the number of signatures
    added. A key signs an input only if its derivation's fingerprint is this
    root's, the derived public key is the one listed, and that key is in the
    script being spent.
    """
    fingerprint = root.my_fingerprint
    count = 0
    for i, inp in enumerate(psbt.inputs):
        if inp.sighash_type != SIGHASH_UNIFIED_ALL:
            continue
        if inp.utxo is not None and inp.is_taproot:
            raise UnifiedSighashError("Input %d: taproot with the unified sighash is not supported" % (i + 1))
        sc = script_code_for(psbt, i)
        h = None
        for pub, der in inp.bip32_derivations.items():
            if der.fingerprint != fingerprint:
                continue
            hd = root.derive(der.derivation)
            if hd.key.sec() != pub.sec():
                raise UnifiedSighashError("Input %d: derivation path does not give the listed key" % (i + 1))
            if pub.sec() not in sc and hashes.hash160(pub.sec()) not in sc:
                continue
            if h is None:
                h = psbt_unified_sighash(psbt, i)
            sig = hd.key.sign(h)
            inp.partial_sigs[pub] = sig.serialize() + bytes([SIGHASH_UNIFIED_ALL])
            count += 1
    return count
