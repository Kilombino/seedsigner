import os

from base import FlowTest, FlowStep

from embit.psbt import PSBT

from seedsigner.models.settings import Settings, SettingsConstants
from seedsigner.views.view import MainMenuView
from seedsigner.views import scan_views, seed_views, psbt_views

# Two-input P2WPKH regtest PSBT from test_flows_psbt.py (with previous transactions).
PSBT_B64 = "cHNidP8BANgCAAAAAsTXZs3fz/dmGb6M80+jjvJZdYya+cw5bT/dGuhZFdSlAAAAAAD9////qo6xg/UZAvUkcbse1F+C9zbP/FeZNjThx7SCIn6eMCgBAAAAAP3///8EQOIBAAAAAAAWABSkZPM7kLcTRE2En1t33/0RCHgMjQXYnnYAAAAAFgAUKMaPRKXdY4m8iKrE9j+rycskJU1A4gEAAAAAABYAFPYc9wiHRrYKAZYLLztREAwpPBIwipVcAwAAAAAWABSiFuiJIa4NrxLUBVQNS0NIun6DDtoRAABPAQQ1h88DBcQGZIAAAAA+0J+jlNL3dpWwlnBi8Dx+Ipg4e6uvB3HdjzFPX7r9CAOOlAIxgII+/xCcj+XoEenKH7wj5s5wlu7Q7CCZWFLGLhA5Su0UVAAAgAEAAIAAAACAAAEA7QIAAAAEE6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0BAAAAAP3///8TqeNf9+e+fuFuQohFzHM1gU5J9sJ015ad3sV7/VRxDQMAAAAA/f///xOp41/3575+4W5CiEXMczWBTkn2wnTXlp3exXv9VHENBAAAAAD9////E6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0GAAAAAP3///8CUnheAwAAAAAWABRCfygPJ+Fjsx4BknYvvm3A3qKn2xJ/XQcAAAAAF6kU1I4TAst5nAj15ey7vwe5cM3OFq+HlhEAAAEBH1J4XgMAAAAAFgAUQn8oDyfhY7MeAZJ2L75twN6ip9sBAwQBAAAAIgYCo7sfm78RQY3B5n0ac/QF8VtMAzFnci+h5D1MtpgRY7oYOUrtFFQAAIABAACAAAAAgAEAAAAGAAAAAAEAcQIAAAABxY7wh0nsfJQfzWrD/9rN9BYsM+iOmPaO6I0ANFgO/PcAAAAAAP3///8CptiUAAAAAAAWABRIm4HhQY/TzOjeWSPRrbuJo9MlW826oHYAAAAAFgAU0z+0L2QSLGtyQTn8FhbCpcI7jbliAQAAAQEfzbqgdgAAAAAWABTTP7QvZBIsa3JBOfwWFsKlwjuNuQEDBAEAAAAiBgITHmebEANk81CraV4xZIpqkNjjw0tIvezl1Ism1NRH3Rg5Su0UVAAAgAEAAIAAAACAAQAAAAAAAAAAIgICuTT7WnuiUTpObjWnZFHzIeEvW9PTB+1LLVFNQJVFeIIYOUrtFFQAAIABAACAAAAAgAEAAAAHAAAAACICAk8f3hpc5C35chgSg+Pe2zZ9IhHREd4aKW2+yAMRIFeqGDlK7RRUAACAAQAAgAAAAIABAAAACQAAAAAAIgIDjt1CjvrnMMnjbmTNKUAYoKEDRbmKjNjbq+6Ppqj3bqQYOUrtFFQAAIABAACAAAAAgAEAAAAIAAAAAA=="
SEEDQR = "080115060387063104071857067618681125136207731354"


def _without_previous_transactions(b64: str) -> str:
    psbt = PSBT.from_string(b64)
    for inp in psbt.inputs:
        inp.non_witness_utxo = None
    return psbt.to_string()


class TestXbtMicroSDAndUnverifiedFlows(FlowTest):

    def _sign_steps(self, psbt_b64, extra_after_mode=()):
        return [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=lambda v: v.decoder.add_data(psbt_b64)),
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=lambda v: v.decoder.add_data(SEEDQR)),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTSigningModeView),
            *extra_after_mode,
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, button_data_selection=0),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
        ]


    def test_signed_psbt_saved_to_microsd(self, tmp_path=None):
        import tempfile
        here = os.getcwd()
        with tempfile.TemporaryDirectory() as card:
            os.chdir(card)  # off SeedSignerOS the working directory stands in for the card
            try:
                self.run_sequence(self._sign_steps(PSBT_B64) + [
                    FlowStep(psbt_views.PSBTSignedExportView, button_data_selection=psbt_views.PSBTSignedExportView.SAVE_SD),
                    FlowStep(psbt_views.PSBTSaveToMicroSDView, button_data_selection=0),
                    FlowStep(MainMenuView),
                ])
                files = os.listdir(card)
                assert len(files) == 1 and files[0].startswith("signed-") and files[0].endswith(".psbt")
                signed = PSBT.parse(open(os.path.join(card, files[0]), "rb").read())
                assert all(inp.partial_sigs or inp.final_scriptwitness for inp in signed.inputs)
            finally:
                os.chdir(here)


    def test_multi_input_segwit_without_previous_transactions_is_warned_not_refused(self):
        # XBT mode off: old-style signatures for the SHA-256 chain.
        Settings.get_instance().set_value(SettingsConstants.SETTING__XBT_MODE, SettingsConstants.OPTION__DISABLED)
        self.run_sequence(self._sign_steps(
            _without_previous_transactions(PSBT_B64),
            extra_after_mode=[FlowStep(psbt_views.PSBTUnverifiedAmountWarningView, button_data_selection=0)],
        ) + [
            FlowStep(psbt_views.PSBTSignedExportView, button_data_selection=psbt_views.PSBTSignedExportView.SHOW_QR),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
            FlowStep(MainMenuView),
        ])
