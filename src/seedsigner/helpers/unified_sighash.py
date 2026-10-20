"""
The unified opt-in signature hash of the Bitcoin BLAKE2b chain (XBT).

A signature whose hash type has the 0x20 bit set (SIGHASH_UNIFIED) is checked
against a different message than the legacy, BIP143 or BIP341 ones: Bitcoin
Knots BLAKE2b, doc/unified-sighash.md and SignatureHashUnified() in
src/script/interpreter.cpp. This fork signs with 0x21 (SIGHASH_UNIFIED |
SIGHASH_ALL) every input when XBT mode is on, and JoinMarket fidelity-bond
inputs always. Two things follow from that message:

* Replay protection. A node that does not know the bit computes the old
  message for the same byte, so the signature does not verify on the SHA-256
  chain the coins share their history with.
* No CVE-2020-14199. Like BIP341, the message commits to the amount and the
  scriptPubKey of EVERY input, not only the one being signed. A coordinator that
  lies about an input amount gets a signature that is invalid on chain, so the
  fee the device shows is the fee that can be paid.

Built here: bare/P2SH (script type 0: P2PKH, legacy P2SH multisig), segwit v0
(script type 1: P2WPKH, P2SH-P2WPKH, P2WSH, P2SH-P2WSH) and the taproot key
path (script type 2). Tapscript (type 3) is not signed.
"""
import hashlib
from typing import List, Optional, Sequence, Tuple

from embit import compact, hashes, script
from embit.psbt import PSBT
from embit.script import Witness


SIGHASH_ALL = 0x01
SIGHASH_UNIFIED = 0x20
SIGHASH_UNIFIED_ALL = SIGHASH_UNIFIED | SIGHASH_ALL  # 0x21

SCRIPT_TYPE_BASE = 0
SCRIPT_TYPE_SEGWIT_V0 = 1
SCRIPT_TYPE_TAPROOT = 2


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
    script_code: bytes = b"",
    annex: Optional[bytes] = None,
) -> bytes:
    """The 32-byte unified sighash, laid out as SignatureHashUnified() writes it.

    `prevouts` are 36-byte outpoints (txid little-endian + vout), `spent_scripts`
    the raw scriptPubKeys, `outputs` (value, raw scriptPubKey) pairs, `script_code`
    the scriptCode without its length prefix (types 0 and 1) and `annex` the
    taproot annex if any (type 2).
    """
    n = len(prevouts)
    if not (len(amounts) == len(spent_scripts) == len(sequences) == n):
        raise UnifiedSighashError("The unified sighash needs every input's amount and script")
    if not 0 <= input_index < n:
        raise UnifiedSighashError("Input index out of range")
    if script_type not in (SCRIPT_TYPE_BASE, SCRIPT_TYPE_SEGWIT_V0, SCRIPT_TYPE_TAPROOT):
        raise UnifiedSighashError("Unsupported script type %d" % script_type)
    if not hash_type & SIGHASH_UNIFIED:
        raise UnifiedSighashError("Hash type 0x%02x did not opt in to the unified sighash" % hash_type)

    anyone_can_pay = bool(hash_type & 0x80)
    output_type = hash_type & 0x1F
    if script_type == SCRIPT_TYPE_TAPROOT:
        # BIP341's reading: only the bytes it defines.
        if hash_type & ~(0x1F | 0x80 | SIGHASH_UNIFIED) or output_type not in (1, 2, 3):
            raise UnifiedSighashError("Hash type 0x%02x is not defined for taproot" % hash_type)

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
    if script_type == SCRIPT_TYPE_TAPROOT:
        msg += b"\x01" + _sha256(_ser_string(annex)) if annex is not None else b"\x00"
    else:
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


def input_kind(psbt: PSBT, i: int) -> Tuple[int, bytes, str]:
    """(script type, scriptCode, kind) of input `i`, from what it spends.

    kind is one of p2pkh, p2sh, p2wpkh, p2sh-p2wpkh, p2wsh, p2sh-p2wsh, p2tr.
    """
    n = i + 1
    inp = psbt.inputs[i]
    spk = inp.utxo.script_pubkey
    kind = spk.script_type()
    if kind == "p2tr":
        if inp.taproot_scripts:
            raise UnifiedSighashError("Input %d: taproot script paths are not signed in XBT mode" % n)
        return SCRIPT_TYPE_TAPROOT, b"", "p2tr"
    if kind == "p2pkh":
        return SCRIPT_TYPE_BASE, spk.data, "p2pkh"
    nested = False
    if kind == "p2sh":
        if inp.redeem_script is None or script.p2sh(inp.redeem_script).data != spk.data:
            raise UnifiedSighashError("Input %d: redeem script missing or not the one the coins are locked to" % n)
        rs_kind = inp.redeem_script.script_type()
        if rs_kind not in ("p2wpkh", "p2wsh"):
            # Legacy P2SH (e.g. multisig): the redeem script is the scriptCode.
            return SCRIPT_TYPE_BASE, inp.redeem_script.data, "p2sh"
        spk, kind, nested = inp.redeem_script, rs_kind, True
    if kind == "p2wpkh":
        return SCRIPT_TYPE_SEGWIT_V0, script.p2pkh_from_p2wpkh(spk).data, "p2sh-p2wpkh" if nested else "p2wpkh"
    if kind == "p2wsh":
        if inp.witness_script is None or script.p2wsh(inp.witness_script).data != spk.data:
            raise UnifiedSighashError("Input %d: witness script missing or not the one the coins are locked to" % n)
        return SCRIPT_TYPE_SEGWIT_V0, inp.witness_script.data, "p2sh-p2wsh" if nested else "p2wsh"
    raise UnifiedSighashError("Input %d: unsupported script type" % n)


def psbt_unified_sighash(psbt: PSBT, i: int, hash_type: int = SIGHASH_UNIFIED_ALL) -> bytes:
    """The unified sighash of input `i` of `psbt` (types 0, 1 and taproot key path)."""
    tx = psbt.tx
    spent = spent_outputs(psbt)
    script_type, script_code, _ = input_kind(psbt, i)
    return unified_message_hash(
        version=tx.version,
        locktime=tx.locktime,
        hash_type=hash_type,
        script_type=script_type,
        prevouts=[bytes(reversed(vin.txid)) + vin.vout.to_bytes(4, "little") for vin in tx.vin],
        amounts=[v for v, _ in spent],
        spent_scripts=[s for _, s in spent],
        sequences=[vin.sequence for vin in tx.vin],
        outputs=[(vout.value, vout.script_pubkey.data) for vout in tx.vout],
        input_index=i,
        script_code=script_code,
    )


def sign_unified(psbt: PSBT, root, inputs: Optional[Sequence[int]] = None) -> int:
    """Sign with 0x21 the inputs in `inputs` (default: those whose
    PSBT_IN_SIGHASH_TYPE is 0x21) with the keys of `root` (an HDKey).

    Each signed input gets PSBT_IN_SIGHASH_TYPE = 0x21 written, so a finalizer
    that compares the field with the signature's last byte agrees. embit's own
    sign_with() must not be run on these inputs: it would sign them with the
    old sighash. Returns the number of signatures added. A key signs an input
    only if its derivation's fingerprint is this root's, the derived public key
    is the one listed, and that key is in what is being spent.
    """
    fingerprint = root.my_fingerprint
    if inputs is None:
        inputs = [i for i, inp in enumerate(psbt.inputs) if inp.sighash_type == SIGHASH_UNIFIED_ALL]
    count = 0
    for i in inputs:
        inp = psbt.inputs[i]
        n = i + 1
        script_type, script_code, kind = input_kind(psbt, i)
        h = None
        if script_type == SCRIPT_TYPE_TAPROOT:
            for pub, (leaf_hashes, der) in inp.taproot_bip32_derivations.items():
                if der.fingerprint != fingerprint or leaf_hashes:
                    continue
                hd = root.derive(der.derivation)
                if hd.xonly() != pub.xonly():
                    raise UnifiedSighashError("Input %d: derivation path does not give the listed key" % n)
                tweaked = hd.key.taproot_tweak(inp.taproot_merkle_root or b"")
                if tweaked.xonly() not in inp.utxo.script_pubkey.data:
                    continue
                h = h or psbt_unified_sighash(psbt, i)
                sig = tweaked.schnorr_sign(h).serialize() + bytes([SIGHASH_UNIFIED_ALL])
                inp.final_scriptwitness = Witness([sig])
                inp.sighash_type = SIGHASH_UNIFIED_ALL
                count += 1
            continue
        for pub, der in inp.bip32_derivations.items():
            if der.fingerprint != fingerprint:
                continue
            hd = root.derive(der.derivation)
            if hd.key.sec() != pub.sec():
                raise UnifiedSighashError("Input %d: derivation path does not give the listed key" % n)
            if kind in ("p2pkh", "p2wpkh", "p2sh-p2wpkh"):
                if hashes.hash160(pub.sec()) not in script_code:
                    continue
            elif pub.sec() not in script_code:
                continue
            h = h or psbt_unified_sighash(psbt, i)
            sig = hd.key.sign(h)
            inp.partial_sigs[pub] = sig.serialize() + bytes([SIGHASH_UNIFIED_ALL])
            inp.sighash_type = SIGHASH_UNIFIED_ALL
            count += 1
    return count
