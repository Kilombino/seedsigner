"""
Reasons this fork refuses to sign a PSBT, raised while it is parsed and shown to
the user instead of the transaction (see views.psbt_views.PSBTRefusedView).

`dire` picks the screen: True for what looks like an attack (red, "Suspicious
Transaction"), False for a PSBT that is merely not signable as it stands
(yellow).
"""


class PSBTRefusal(Exception):
    dire = True


class PSBTMissingInputUtxoError(PSBTRefusal):
    """An input carries neither witness_utxo nor non_witness_utxo: no amount to show."""
    dire = False


class PSBTInputAmountVerificationError(PSBTRefusal):
    """An input's declared amount is unproven or contradicted (upstream PR #995,
    plus the CVE-2020-14199 rule for multi-input segwit v0 signed the old way)."""
    dire = True


class PSBTSighashModeError(PSBTRefusal):
    """The PSBT asks for a sighash the current XBT mode does not sign."""
    dire = False
