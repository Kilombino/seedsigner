"""
JoinMarket fidelity bonds, as a PSBT input SeedSigner can recognise and sign.

A JoinMarket wallet keeps its timelocked fidelity bonds on mixdepth 0, branch 2:
the key of a bond is m/84'/<coin>'/0'/2/<timenumber>, where the timenumber
counts months since January 2020 and fixes the locktime (the 1st of that month,
00:00 UTC; jmcore.timenumber / jmclient FidelityBondMixin). The coins sit in a
P2WSH of exactly

    <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <33-byte pubkey> OP_CHECKSIG

(jmcore.btc_script.mk_freeze_script). Spending one needs nLockTime >= locktime
(same kind: a time, not a height) and a non-final sequence on the input, and the
finished witness is <signature> <witness script>.

Nothing here trusts the coordinator's labels: the locktime is read from the
script, the key is derived from the seed and compared, and the derivation index
must be the timenumber of that very locktime.
"""
from gettext import gettext as _
import calendar
import datetime
from binascii import hexlify
from dataclasses import dataclass
from typing import Optional

from embit import bip32, script
from embit.psbt import PSBT

from seedsigner.models.psbt_refusal import PSBTRefusal


OP_CHECKLOCKTIMEVERIFY = 0xB1
OP_DROP = 0x75
OP_CHECKSIG = 0xAC

BOND_BRANCH = 2
TIMENUMBER_COUNT = 960            # Jan 2020 .. Dec 2099
LOCKTIME_THRESHOLD = 500_000_000  # below: a block height; at or above: a unix time
SEQUENCE_FINAL = 0xFFFFFFFF
HARDENED = 0x80000000


class FidelityBondError(PSBTRefusal):
    """A bond input that must not be signed. The message is shown to the user."""
    dire = True


def timenumber_to_locktime(timenumber: int) -> int:
    if not 0 <= timenumber < TIMENUMBER_COUNT:
        raise ValueError("timenumber out of range")
    year = 2020 + timenumber // 12
    month = 1 + timenumber % 12
    return calendar.timegm((year, month, 1, 0, 0, 0))


def locktime_to_timenumber(locktime: int) -> Optional[int]:
    """The timenumber of a locktime, or None if it is not the 1st of a month 00:00 UTC."""
    if locktime < LOCKTIME_THRESHOLD:
        return None
    d = datetime.datetime.fromtimestamp(locktime, tz=datetime.timezone.utc)
    tn = (d.year - 2020) * 12 + (d.month - 1)
    if 0 <= tn < TIMENUMBER_COUNT and timenumber_to_locktime(tn) == locktime:
        return tn
    return None


def locktime_date(locktime: int) -> str:
    """'2026-11-01' (UTC), as JoinMarket and Jam print a bond's locktime."""
    return datetime.datetime.fromtimestamp(locktime, tz=datetime.timezone.utc).strftime("%Y-%m-%d")


def _read_script_num(data: bytes) -> int:
    """A minimally-encoded CScriptNum (as CHECKLOCKTIMEVERIFY reads it, up to 5 bytes)."""
    if len(data) == 0 or len(data) > 5:
        raise ValueError("bad number")
    if data[-1] & 0x7F == 0 and (len(data) == 1 or not data[-2] & 0x80):
        raise ValueError("non-minimal number")
    v = int.from_bytes(data, "little")
    if data[-1] & 0x80:
        v = -(v & ~(0x80 << (8 * (len(data) - 1))))
    return v


def parse_bond_script(witness_script: bytes):
    """(locktime, pubkey_sec) if `witness_script` is exactly JoinMarket's bond
    template, otherwise None."""
    s = bytes(witness_script)
    if len(s) < 1:
        return None
    n = s[0]
    if not 1 <= n <= 5 or len(s) != 1 + n + 2 + 1 + 33 + 1:
        return None
    try:
        locktime = _read_script_num(s[1:1 + n])
    except ValueError:
        return None
    rest = s[1 + n:]
    if rest[0] != OP_CHECKLOCKTIMEVERIFY or rest[1] != OP_DROP or rest[2] != 33 or rest[-1] != OP_CHECKSIG:
        return None
    pubkey = rest[3:36]
    if pubkey[0] not in (2, 3) or locktime <= 0:
        return None
    return locktime, pubkey


def make_bond_script(locktime: int, pubkey_sec: bytes) -> bytes:
    """The template, built the way python-bitcointx builds it (minimal push)."""
    n = locktime.to_bytes((locktime.bit_length() + 8) // 8, "little")
    # Drop a needless trailing zero byte (minimal CScriptNum encoding).
    while len(n) > 1 and n[-1] == 0 and not n[-2] & 0x80:
        n = n[:-1]
    return bytes([len(n)]) + n + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP, 33]) + pubkey_sec + bytes([OP_CHECKSIG])


@dataclass
class BondInput:
    input_index: int
    amount: int
    locktime: int
    timenumber: int
    pubkey: bytes
    fingerprint: str
    derivation_path: str

    @property
    def unlock_date(self) -> str:
        return locktime_date(self.locktime)


def is_bond_input(psbt: PSBT, i: int) -> bool:
    """Whether input `i` claims to spend a JoinMarket bond (P2WSH + the template)."""
    inp = psbt.inputs[i]
    utxo = inp.utxo
    if utxo is None or utxo.script_pubkey.script_type() != "p2wsh" or inp.witness_script is None:
        return False
    return parse_bond_script(inp.witness_script.data) is not None


def check_bond_input(psbt: PSBT, i: int, root: bip32.HDKey, coin_type: int) -> BondInput:
    """Everything that must hold before SeedSigner signs bond input `i`.

    Raises FidelityBondError with a short, user-facing reason otherwise.
    `root` is the master key of the selected seed, `coin_type` 0 on mainnet and 1
    on the test networks (BIP44 coin types, as JoinMarket uses them).
    """
    n = i + 1
    inp = psbt.inputs[i]
    vin = psbt.tx.vin[i]
    utxo = inp.utxo
    ws = inp.witness_script.data
    locktime, pubkey = parse_bond_script(ws)

    if script.p2wsh(inp.witness_script).data != utxo.script_pubkey.data:
        raise FidelityBondError(_("Bond input {}: the witness script is not the one the coins are locked to.").format(n))

    # (The sighash is not checked here: a bond is always signed 0x21, whatever
    # the PSBT asks and whatever the XBT mode; see PSBTParser._plan_sighashes.)

    # If the coordinator sent the previous transaction, it must be the real one.
    if inp.non_witness_utxo is not None:
        if inp.non_witness_utxo.txid() != vin.txid:
            raise FidelityBondError(_("Bond input {}: the previous transaction does not match its txid.").format(n))
        prev_out = inp.non_witness_utxo.vout[vin.vout]
        if inp.witness_utxo is not None and (
            prev_out.value != inp.witness_utxo.value
            or prev_out.script_pubkey.data != inp.witness_utxo.script_pubkey.data
        ):
            raise FidelityBondError(_("Bond input {}: the amount does not match the previous transaction.").format(n))

    # Timelock: the transaction must be valid once the bond unlocks, never earlier.
    if locktime < LOCKTIME_THRESHOLD:
        raise FidelityBondError(_("Bond input {} is locked to a block height, not a date. Not a JoinMarket bond.").format(n))
    if psbt.tx.locktime < LOCKTIME_THRESHOLD or psbt.tx.locktime < locktime:
        raise FidelityBondError(_("Bond input {}: the transaction's locktime is before the bond unlocks.").format(n))
    if vin.sequence == SEQUENCE_FINAL:
        raise FidelityBondError(_("Bond input {}: a final sequence would disable the timelock.").format(n))

    timenumber = locktime_to_timenumber(locktime)
    if timenumber is None:
        raise FidelityBondError(_("Bond input {}: its locktime is not the 1st of a month. Not a JoinMarket bond.").format(n))

    # The key: listed, ours, and at the bond path of that very timenumber.
    pub_obj = None
    der = None
    for p, d in inp.bip32_derivations.items():
        if p.sec() == pubkey:
            pub_obj, der = p, d
    if der is None:
        raise FidelityBondError(_("Bond input {}: the PSBT does not say which key of this seed it uses.").format(n))
    expected = [84 + HARDENED, coin_type + HARDENED, 0 + HARDENED, BOND_BRANCH, timenumber]
    if list(der.derivation) != expected:
        raise FidelityBondError(_("Bond input {}: expected key {}, the PSBT says {}.").format(n, bip32.path_to_str(expected), bip32.path_to_str(der.derivation)))
    if der.fingerprint != root.my_fingerprint:
        raise FidelityBondError(_("Bond input {} belongs to another seed.").format(n))
    if root.derive(der.derivation).key.sec() != pubkey:
        raise FidelityBondError(_("Bond input {}: this seed does not derive the bond's key.").format(n))

    return BondInput(
        input_index=i,
        amount=utxo.value,
        locktime=locktime,
        timenumber=timenumber,
        pubkey=pubkey,
        fingerprint=hexlify(der.fingerprint).decode(),
        derivation_path=bip32.path_to_str(der.derivation),
    )
