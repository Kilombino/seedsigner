from embit.psbt import PSBT

from seedsigner.helpers.psbt_file import save_signed_psbt, signed_filename

# A small valid PSBT (BIP174 test vector, one input/two outputs).
B64 = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA"


def test_save_signed_psbt_writes_binary_and_never_overwrites(tmp_path):
    psbt = PSBT.from_string(B64)
    first = save_signed_psbt(psbt, str(tmp_path))
    second = save_signed_psbt(psbt, str(tmp_path))
    assert first.startswith("signed-") and first.endswith(".psbt")
    assert second == first[:-5] + "-2.psbt"
    data = (tmp_path / first).read_bytes()
    assert data.startswith(b"psbt\xff")
    assert PSBT.parse(data).serialize() == psbt.serialize()


def test_signed_filename_uses_txid_prefix():
    psbt = PSBT.from_string(B64)
    name = signed_filename(psbt, set())
    assert name == "signed-" + psbt.tx.txid().hex()[:12] + ".psbt"
