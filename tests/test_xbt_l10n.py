"""XBT fork: every string the fork adds is translated to Spanish (l10n/xbt-es.po,
appended to the translations submodule's es catalog on branch xbt)."""
import os

from babel.messages.pofile import read_po

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ids(path):
    return {m.id: m.string for m in read_po(open(path, "rb")) if m.id}


def test_every_xbt_string_is_in_the_pot_and_translated_to_spanish():
    xbt = _ids(os.path.join(ROOT, "l10n", "xbt-es.po"))
    pot = _ids(os.path.join(ROOT, "l10n", "messages.pot"))
    es = _ids(os.path.join(ROOT, "src", "seedsigner", "resources", "seedsigner-translations", "l10n", "es", "LC_MESSAGES", "messages.po"))
    assert len(xbt) == 42
    for msgid, msgstr in xbt.items():
        assert msgid in pot, msgid
        assert es.get(msgid) == msgstr and msgstr, msgid
