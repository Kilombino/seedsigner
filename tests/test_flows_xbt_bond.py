"""
XBT: the screens a JoinMarket fidelity-bond spend goes through, and the refusal.
"""
from base import FlowTest, FlowStep

from seedsigner.controller import Controller
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import psbt_views, scan_views
from seedsigner.views.view import MainMenuView

from test_xbt_fidelity_bond import JAM_SIGNATURE, MNEMONIC, bond_psbt


class TestXbtBondFlows(FlowTest):

    def _load(self, psbt):
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)
        self.controller.storage.set_pending_seed(Seed(MNEMONIC.split()))
        self.controller.storage.finalize_pending_seed()

        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(psbt.to_string())
        return load_psbt_into_decoder

    def test_bond_spend_flow(self):
        """Overview -> bond screen -> full spend -> math -> destination -> sign -> signed QR."""
        load = self._load(bond_psbt())
        signed = []

        def grab(view):
            signed.append(self.controller.psbt)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load),
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView, screen_return_value=0),
            FlowStep(psbt_views.PSBTFidelityBondView, screen_return_value=0),
            FlowStep(psbt_views.PSBTNoChangeWarningView, screen_return_value=0),
            FlowStep(psbt_views.PSBTMathView, screen_return_value=0),
            FlowStep(psbt_views.PSBTAddressDetailsView, screen_return_value=0),
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView, before_run=grab),
            FlowStep(MainMenuView),
        ])
        (sig,) = signed[0].inputs[0].partial_sigs.values()
        assert sig.hex() == JAM_SIGNATURE

    def test_bond_without_unified_sighash_is_refused(self):
        load = self._load(bond_psbt(sighash=None))
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load),
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
            FlowStep(psbt_views.PSBTRefusedView, screen_return_value=0),
            FlowStep(MainMenuView),
        ])
