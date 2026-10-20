"""
XBT: the unified sighash (0x21) and JoinMarket fidelity-bond spends.

The regtest vector is a real bond spend: created and spent from Jam
(JoinMarket-NG, XBT fork) on a private Bitcoin Knots BLAKE2b regtest and mined
there. txid 3d998f50...c48f, nLockTime 1793491200 (2026-11-01), one input
signed 0x21 by libsecp256k1. ECDSA here is RFC6979 with the same low-R
grinding, so signing that sighash with that key must give the very same bytes.
The seed is the throwaway regtest wallet that made it.
"""
import copy
import json
import os

import pytest
from embit import bip32, bip39, ec, script
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionOutput

from seedsigner.helpers.unified_sighash import (
    SIGHASH_UNIFIED_ALL, UnifiedSighashError, psbt_unified_sighash, sign_unified, unified_message_hash)
from seedsigner.models import fidelity_bond
from seedsigner.models.fidelity_bond import FidelityBondError
from seedsigner.models.psbt_refusal import PSBTInputAmountVerificationError, PSBTRefusal, PSBTSighashModeError
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants


MNEMONIC = "hair horse robot tent betray wedding judge moon tower swallow yellow episode"
FINGERPRINT = "c47272bb"
BOND_PATH = "m/84h/1h/0h/2/82"
BOND_PUBKEY = "03808f8a4d55173b9a3f9a259835f7ce7069321700ebcf2a0fc5892b2649fe134a"
BOND_LOCKTIME = 1793491200
WITNESS_SCRIPT = "040081e66ab1752103808f8a4d55173b9a3f9a259835f7ce7069321700ebcf2a0fc5892b2649fe134aac"
BOND_VALUE = 50_000_000

FUND_TX = (
    "02000000000101e6e20508e97aa2dc465bd954b4784f6fb5666945c6275cfd38f99ca486acb5ee0000000000fdffffff0280f0fa02"
    "000000002200200981dcf3b36f7610d26a17c896aa195e818394f83fc565a2d9dd796f0ebd6f09d7effa020000000016001444ac90"
    "d18c8b8f5436ade8fecbe5f4adfea16c6e0247304402206b9566d11a48e5c87579af8dac230b895e1cac1276fb15492aa55143ce1c"
    "9d20022048ace4079206bb3f804fc982242f03c485a1fb1c40c82bd73277e9961519d23c212103acc2b0bcf1697324a3013f4fb7cc"
    "8d59de0aa576a208126205073bd2e770335205010000"
)
SPEND_TX = (
    "020000000001017cb05f78443ec01cd3d31d30980567fb833242b483a5c682bdd317e1a415c6720000000000fdffffff01fceffa02"
    "000000001600143a0b72fbc9d6cc43acec4ababfa90fce584269010247304402203d33ee140d1cb9fa8413b141b585f3b6e9c5b4ca"
    "5a78753d35a86dc7fbe1156102207b14f4e2abd78c0fafe1a95ba304d77e2149912ea1e76ca3e1342f5b61306945212a040081e66a"
    "b1752103808f8a4d55173b9a3f9a259835f7ce7069321700ebcf2a0fc5892b2649fe134aac0081e66a"
)
SPEND_TXID = "3d998f5055a04a66a2f70a870bd3b4887cb6beccdd2ed8503c8098d6a4e5c48f"
# The signature Jam put in the witness (DER + 0x21).
JAM_SIGNATURE = (
    "304402203d33ee140d1cb9fa8413b141b585f3b6e9c5b4ca5a78753d35a86dc7fbe1156102207b14f4e2abd78c0fafe1a95ba304d7"
    "7e2149912ea1e76ca3e1342f5b6130694521"
)


def seed():
    return Seed(MNEMONIC.split())


def root():
    return bip32.HDKey.from_seed(bip39.mnemonic_to_seed(MNEMONIC))


def bond_psbt(non_witness=True, sighash=SIGHASH_UNIFIED_ALL, fingerprint=FINGERPRINT, path=BOND_PATH) -> PSBT:
    """The unsigned PSBT of the regtest spend, as a watch-only coordinator makes it."""
    spent = Transaction.parse(bytes.fromhex(SPEND_TX))
    for vin in spent.vin:
        vin.witness = script.Witness([])
    psbt = PSBT(Transaction.parse(spent.serialize()))
    inp = psbt.inputs[0]
    fund = Transaction.parse(bytes.fromhex(FUND_TX))
    inp.witness_utxo = TransactionOutput(fund.vout[0].value, fund.vout[0].script_pubkey)
    if non_witness:
        inp.non_witness_utxo = fund
    inp.witness_script = script.Script(bytes.fromhex(WITNESS_SCRIPT))
    inp.bip32_derivations[ec.PublicKey.parse(bytes.fromhex(BOND_PUBKEY))] = DerivationPath(
        bytes.fromhex(fingerprint), bip32.parse_path(path))
    if sighash is not None:
        inp.sighash_type = sighash
    return psbt


def roundtrip(psbt: PSBT) -> PSBT:
    return PSBT.parse(psbt.serialize())


def finalize(psbt: PSBT) -> Transaction:
    tx = copy.deepcopy(psbt.tx)
    for i, inp in enumerate(psbt.inputs):
        (sig,) = inp.partial_sigs.values()
        tx.vin[i].witness = script.Witness([sig, inp.witness_script.data])
    return tx


# ------------------------------------------------------------------ the sighash itself

class TestUnifiedSighash:
    def test_knots_vectors(self):
        """Every script-type 0, 1 and 2 vector of Knots' unified_sighash.json."""
        path = os.path.join(os.path.dirname(__file__), "data", "unified_sighash.json")
        rows = json.load(open(path))[1:]
        checked = 0
        for sc, raw, idx, hash_type, script_type, spent, expected in rows:
            if script_type not in (0, 1, 2):
                continue
            tx = Transaction.parse(bytes.fromhex(raw))
            w = tx.vin[idx].witness.items if tx.vin[idx].witness else []
            annex = w[-1] if script_type == 2 and len(w) >= 2 and w[-1][:1] == b"\x50" else None
            h = unified_message_hash(
                version=tx.version, locktime=tx.locktime, hash_type=hash_type, script_type=script_type,
                prevouts=[bytes(reversed(v.txid)) + v.vout.to_bytes(4, "little") for v in tx.vin],
                amounts=[a for a, _ in spent], spent_scripts=[bytes.fromhex(s) for _, s in spent],
                sequences=[v.sequence for v in tx.vin],
                outputs=[(o.value, o.script_pubkey.data) for o in tx.vout],
                input_index=idx, script_code=bytes.fromhex(sc), annex=annex)
            assert h.hex() == expected
            checked += 1
        assert checked == 154   # every bare/P2SH, segwit v0 and taproot key-path vector

    def test_refuses_hash_type_without_the_unified_bit(self):
        with pytest.raises(UnifiedSighashError):
            unified_message_hash(version=2, locktime=0, hash_type=0x01, script_type=1, prevouts=[b"\0" * 36],
                                 amounts=[1], spent_scripts=[b""], sequences=[0], outputs=[], input_index=0,
                                 script_code=b"")

    def test_commits_to_the_amount_cve_2020_14199(self):
        """Lying about an input amount changes what is signed, so the lie cannot pay a hidden fee."""
        honest = bond_psbt(non_witness=False)
        liar = bond_psbt(non_witness=False)
        liar.inputs[0].witness_utxo.value -= 10_000_000
        assert psbt_unified_sighash(honest, 0) != psbt_unified_sighash(liar, 0)


# ------------------------------------------------------------------ the regtest vector

class TestRegtestBondVector:
    def test_signature_is_byte_identical_to_jams(self):
        """RFC6979: same key, same 0x21 sighash -> the very signature Jam broadcast."""
        psbt = roundtrip(bond_psbt())
        parser = PSBTParser(psbt, seed=seed(), network=SettingsConstants.REGTEST)
        assert psbt.sign_with(parser.root) == 0     # embit leaves 0x21 inputs alone
        assert sign_unified(psbt, parser.root) == 1
        (sig,) = psbt.inputs[0].partial_sigs.values()
        assert sig.hex() == JAM_SIGNATURE

    def test_finalized_transaction_is_the_mined_one(self):
        psbt = roundtrip(bond_psbt())
        sign_unified(psbt, root())
        signed = PSBTParser.trim(psbt)
        tx = finalize(psbt)
        assert tx.serialize().hex() == SPEND_TX
        assert tx.txid().hex() == SPEND_TXID
        assert PSBTParser.sig_count(signed) == 1

    def test_signature_verifies_against_the_unified_sighash(self):
        psbt = roundtrip(bond_psbt())
        sign_unified(psbt, root())
        (pub, sig), = psbt.inputs[0].partial_sigs.items()
        assert sig[-1] == SIGHASH_UNIFIED_ALL
        assert pub.verify(ec.Signature.parse(sig[:-1]), psbt_unified_sighash(psbt, 0))

    def test_parser_reads_the_bond(self):
        psbt = roundtrip(bond_psbt())
        parser = PSBTParser(psbt, seed=seed(), network=SettingsConstants.REGTEST)
        assert parser.is_bond_spend
        assert parser.has_unified_sighash
        (bond,) = parser.bond_inputs
        assert bond.amount == BOND_VALUE
        assert bond.locktime == BOND_LOCKTIME
        assert bond.unlock_date == "2026-11-01"
        assert bond.timenumber == 82
        assert bond.fingerprint == FINGERPRINT
        assert bond.derivation_path == "m/84h/1h/0h/2/82"
        assert parser.input_amount == BOND_VALUE
        assert parser.fee_amount == BOND_VALUE - 49_999_868
        assert parser.spend_amount == 49_999_868
        assert parser.destination_addresses == ["bcrt1q8g9h977f6mxy8t8vf2atl2g0eevyy6gpne8l0k"]
        assert parser.change_amount == 0
        assert not parser.is_multisig

    def test_witness_utxo_alone_is_enough(self):
        """0x21 commits to the amounts, so the previous transaction is optional."""
        psbt = roundtrip(bond_psbt(non_witness=False))
        parser = PSBTParser(psbt, seed=seed(), network=SettingsConstants.REGTEST)
        assert parser.is_bond_spend
        assert sign_unified(psbt, parser.root) == 1
        (sig,) = psbt.inputs[0].partial_sigs.values()
        assert sig.hex() == JAM_SIGNATURE

    def test_missing_fingerprint_is_filled_from_the_seed(self):
        """A coordinator that only has the zpub writes 00000000; the seed proves the key is its own."""
        psbt = roundtrip(bond_psbt(fingerprint="00000000"))
        assert PSBTParser.has_matching_input_fingerprint(psbt, seed(), network=SettingsConstants.REGTEST)
        parser = PSBTParser(psbt, seed=seed(), network=SettingsConstants.REGTEST)
        assert parser.bond_inputs[0].fingerprint == FINGERPRINT
        assert sign_unified(psbt, parser.root) == 1
        assert list(psbt.inputs[0].partial_sigs.values())[0].hex() == JAM_SIGNATURE


# ------------------------------------------------------------------ what must be refused

def _parse(psbt, xbt_mode=False):
    return PSBTParser(roundtrip(psbt), seed=seed(), network=SettingsConstants.REGTEST, xbt_mode=xbt_mode)


class TestBondSighash:
    """A bond is signed 0x21 whatever the PSBT names (None/0x01/0x21) and whatever the mode."""

    @pytest.mark.parametrize("asked", [None, 0x01, SIGHASH_UNIFIED_ALL])
    @pytest.mark.parametrize("xbt_mode", [False, True])
    def test_always_0x21(self, asked, xbt_mode):
        psbt = roundtrip(bond_psbt(sighash=asked))
        parser = PSBTParser(psbt, seed=seed(), network=SettingsConstants.REGTEST, xbt_mode=xbt_mode)
        assert parser.unified_inputs == [0] and parser.all_unified
        parser.sign()
        trimmed = PSBTParser.trim(psbt)
        assert trimmed.inputs[0].sighash_type == SIGHASH_UNIFIED_ALL   # finalizers agree with the sig
        (sig,) = trimmed.inputs[0].partial_sigs.values()
        assert sig.hex() == JAM_SIGNATURE

    @pytest.mark.parametrize("asked", [0x02, 0x03, 0x81, 0x22, 0xa1])
    def test_other_hash_types_are_refused(self, asked):
        with pytest.raises(PSBTSighashModeError):
            _parse(bond_psbt(sighash=asked))


class TestRefusals:
    def test_locktime_before_the_bond_unlocks(self):
        p = bond_psbt()
        p.locktime = BOND_LOCKTIME - 1
        with pytest.raises(FidelityBondError, match="locktime"):
            _parse(p)

    def test_height_locktime(self):
        p = bond_psbt()
        p.locktime = 300
        with pytest.raises(FidelityBondError, match="locktime"):
            _parse(p)

    def test_final_sequence(self):
        p = bond_psbt()
        p.inputs[0].sequence = 0xFFFFFFFF
        with pytest.raises(FidelityBondError, match="sequence"):
            _parse(p)

    def test_wrong_timenumber_in_the_path(self):
        with pytest.raises(FidelityBondError, match="expected key"):
            _parse(bond_psbt(path="m/84h/1h/0h/2/81"))

    def test_wrong_branch(self):
        with pytest.raises(FidelityBondError, match="expected key"):
            _parse(bond_psbt(path="m/84h/1h/0h/0/82"))

    def test_mainnet_coin_type_on_regtest(self):
        with pytest.raises(FidelityBondError, match="expected key"):
            _parse(bond_psbt(path="m/84h/0h/0h/2/82"))

    def test_another_seeds_bond(self):
        with pytest.raises(FidelityBondError, match="another seed"):
            _parse(bond_psbt(fingerprint="deadbeef"))

    def test_previous_transaction_that_is_not_the_one_spent(self):
        p = bond_psbt()
        other = Transaction.parse(bytes.fromhex(SPEND_TX))
        p.inputs[0].non_witness_utxo = other
        with pytest.raises(PSBTInputAmountVerificationError, match="previous transaction"):
            _parse(p)

    def test_amount_that_disagrees_with_the_previous_transaction(self):
        p = bond_psbt()
        p.inputs[0].witness_utxo.value = BOND_VALUE - 1
        with pytest.raises(PSBTInputAmountVerificationError, match="amount"):
            _parse(p)

    def test_witness_script_of_another_address(self):
        p = bond_psbt(non_witness=False)
        other_script = fidelity_bond.make_bond_script(BOND_LOCKTIME + 2678400, bytes.fromhex(BOND_PUBKEY))
        p.inputs[0].witness_script = script.Script(other_script)
        with pytest.raises(PSBTRefusal):
            _parse(p)


# ------------------------------------------------------------------ the template

class TestTemplate:
    def test_parse_and_build_agree_with_jam(self):
        locktime, pubkey = fidelity_bond.parse_bond_script(bytes.fromhex(WITNESS_SCRIPT))
        assert locktime == BOND_LOCKTIME and pubkey.hex() == BOND_PUBKEY
        assert fidelity_bond.make_bond_script(locktime, pubkey).hex() == WITNESS_SCRIPT

    def test_every_timenumber_round_trips(self):
        for tn in range(fidelity_bond.TIMENUMBER_COUNT):
            lt = fidelity_bond.timenumber_to_locktime(tn)
            assert fidelity_bond.locktime_to_timenumber(lt) == tn
            locktime, _ = fidelity_bond.parse_bond_script(fidelity_bond.make_bond_script(lt, bytes.fromhex(BOND_PUBKEY)))
            assert locktime == lt
        assert fidelity_bond.timenumber_to_locktime(0) == 1577836800
        assert fidelity_bond.locktime_to_timenumber(BOND_LOCKTIME + 1) is None

    def test_not_the_template(self):
        ws = bytes.fromhex(WITNESS_SCRIPT)
        assert fidelity_bond.parse_bond_script(ws[:-1] + b"\xad") is None   # CHECKSIGVERIFY
        assert fidelity_bond.parse_bond_script(ws[:5] + b"\xb2" + ws[6:]) is None   # CSV, not CLTV
        assert fidelity_bond.parse_bond_script(ws + b"\x51") is None
        assert fidelity_bond.parse_bond_script(b"\x05\x00\x81\xe6\x6a\x00" + ws[5:]) is None   # non-minimal


# ------------------------------------------------------------------ 0x21 on an ordinary input

def _single_input_psbt(spk, derivations, value=100_000, sighash=None, taproot=False, n_inputs=1, non_witness=False):
    """A PSBT spending `n_inputs` coins locked to `spk` (the regtest spend's outputs)."""
    tx = Transaction.parse(bytes.fromhex(SPEND_TX))
    tx.vin[0].witness = script.Witness([])
    tx.locktime = 0
    tx.vin[0].sequence = 0xFFFFFFFD
    for k in range(1, n_inputs):
        vin = copy.deepcopy(tx.vin[0]); vin.vout = k; tx.vin.append(vin)
    psbt = PSBT(Transaction.parse(tx.serialize()))
    for inp in psbt.inputs:
        if non_witness:
            prev = Transaction.parse(bytes.fromhex(FUND_TX))
            prev.vout = [TransactionOutput(value, spk) for _ in range(n_inputs)]
            inp.non_witness_utxo = prev
            # point at the fake previous transaction
        else:
            inp.witness_utxo = TransactionOutput(value, spk)
        for pub, der in derivations:
            if taproot:
                inp.taproot_bip32_derivations[pub] = ([], der)
            else:
                inp.bip32_derivations[pub] = der
        if sighash is not None:
            inp.sighash_type = sighash
    if non_witness:
        txid = psbt.inputs[0].non_witness_utxo.txid()
        for k, vin in enumerate(psbt.tx.vin):
            psbt.inputs[k].txid = txid
    return roundtrip(psbt)


def _key(path):
    r = root()
    child = r.derive(path)
    return child, child.key.get_public_key(), DerivationPath(r.my_fingerprint, bip32.parse_path(path))


class TestXbtMode:
    @pytest.mark.parametrize("asked", [None, 0x01, SIGHASH_UNIFIED_ALL])
    def test_p2wpkh_signed_0x21_whatever_it_asks(self, asked):
        _, pub, der = _key("m/84h/1h/0h/0/0")
        psbt = _single_input_psbt(script.p2wpkh(pub), [(pub, der)], sighash=asked)
        parser = _parse_xbt(psbt)
        assert parser.all_unified and not parser.is_bond_spend
        parser.sign()
        trimmed = PSBTParser.trim(psbt)
        assert trimmed.inputs[0].sighash_type == SIGHASH_UNIFIED_ALL
        (signer, sig), = trimmed.inputs[0].partial_sigs.items()
        assert sig[-1] == SIGHASH_UNIFIED_ALL
        assert signer.verify(ec.Signature.parse(sig[:-1]), psbt_unified_sighash(psbt, 0))

    def test_p2sh_p2wpkh_and_p2pkh(self):
        _, pub, der = _key("m/49h/1h/0h/0/0")
        psbt = _single_input_psbt(script.p2sh(script.p2wpkh(pub)), [(pub, der)])
        psbt.inputs[0].redeem_script = script.p2wpkh(pub)
        psbt = roundtrip(psbt)
        parser = _parse_xbt(psbt); parser.sign()
        (signer, sig), = psbt.inputs[0].partial_sigs.items()
        assert signer.verify(ec.Signature.parse(sig[:-1]), psbt_unified_sighash(psbt, 0))

        _, pub, der = _key("m/44h/1h/0h/0/0")
        psbt = _single_input_psbt(script.p2pkh(pub), [(pub, der)])
        parser = _parse_xbt(psbt); parser.sign()
        (signer, sig), = psbt.inputs[0].partial_sigs.items()
        assert signer.verify(ec.Signature.parse(sig[:-1]), psbt_unified_sighash(psbt, 0))

    def test_taproot_key_path(self):
        child, pub, der = _key("m/86h/1h/0h/0/0")
        tweaked = child.key.taproot_tweak(b"")
        psbt = _single_input_psbt(script.p2tr(pub), [(pub, der)], taproot=True)
        parser = _parse_xbt(psbt)
        parser.sign()
        trimmed = PSBTParser.trim(psbt)
        (sig,) = trimmed.inputs[0].final_scriptwitness.items
        assert len(sig) == 65 and sig[-1] == SIGHASH_UNIFIED_ALL
        assert tweaked.get_public_key().schnorr_verify(ec.SchnorrSig.parse(sig[:64]), psbt_unified_sighash(psbt, 0))

    @pytest.mark.parametrize("asked", [0x02, 0x03, 0x81, 0x83])
    def test_exotic_hash_types_are_refused(self, asked):
        _, pub, der = _key("m/84h/1h/0h/0/0")
        with pytest.raises(PSBTSighashModeError):
            _parse_xbt(_single_input_psbt(script.p2wpkh(pub), [(pub, der)], sighash=asked))

    def test_multi_input_segwit_without_prev_tx_is_fine_with_0x21(self):
        _, pub, der = _key("m/84h/1h/0h/0/0")
        psbt = _single_input_psbt(script.p2wpkh(pub), [(pub, der)], n_inputs=2)
        parser = _parse_xbt(psbt)
        parser.sign()
        assert PSBTParser.sig_count(psbt) == 2


def _parse_xbt(psbt):
    return PSBTParser(psbt, seed=seed(), network=SettingsConstants.REGTEST, xbt_mode=True)


class TestXbtModeOff:
    def test_psbt_asking_for_0x21_is_refused(self):
        _, pub, der = _key("m/84h/1h/0h/0/0")
        with pytest.raises(PSBTSighashModeError, match="Turn on XBT mode"):
            _parse(_single_input_psbt(script.p2wpkh(pub), [(pub, der)], sighash=SIGHASH_UNIFIED_ALL))

    def test_plain_psbt_signs_the_old_way(self):
        _, pub, der = _key("m/84h/1h/0h/0/0")
        psbt = _single_input_psbt(script.p2wpkh(pub), [(pub, der)])
        parser = _parse(psbt)
        assert not parser.has_unified_sighash
        parser.sign()
        assert list(parser.psbt.inputs[0].partial_sigs.values())[0][-1] == 0x01
        assert PSBTParser.trim(parser.psbt).inputs[0].sighash_type is None

    def test_multi_input_segwit_needs_previous_transactions(self):
        """CVE-2020-14199: stricter than upstream for old-style signatures."""
        _, pub, der = _key("m/84h/1h/0h/0/0")
        with pytest.raises(PSBTInputAmountVerificationError, match="CVE-2020-14199"):
            _parse(_single_input_psbt(script.p2wpkh(pub), [(pub, der)], n_inputs=2))
        psbt = _single_input_psbt(script.p2wpkh(pub), [(pub, der)], n_inputs=2, non_witness=True)
        parser = _parse(psbt)
        assert parser.input_amount == 200_000
        parser.sign()
        assert PSBTParser.sig_count(parser.psbt) == 2

    def test_legacy_without_previous_transaction_is_refused(self):
        _, pub, der = _key("m/44h/1h/0h/0/0")
        with pytest.raises(PSBTInputAmountVerificationError):
            _parse(_single_input_psbt(script.p2pkh(pub), [(pub, der)]))

    def test_input_without_any_utxo_is_refused(self):
        _, pub, der = _key("m/84h/1h/0h/0/0")
        psbt = _single_input_psbt(script.p2wpkh(pub), [(pub, der)])
        psbt.inputs[0].witness_utxo = None
        with pytest.raises(PSBTRefusal):
            _parse(psbt)


class TestSettingsQR:
    def test_xbt_mode_setting(self):
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsDefinition
        entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__XBT_MODE)
        assert entry.abbreviated_name == "xbt"
        assert entry.default_value == SettingsConstants.OPTION__ENABLED
        name, parsed = Settings.parse_settingsqr("settings::v1 name=Phone xbt=D")
        assert parsed[SettingsConstants.SETTING__XBT_MODE] == SettingsConstants.OPTION__DISABLED
