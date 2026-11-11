"""
XBT fork: write a signed PSBT to the microSD card as a .psbt file.

SeedSignerOS runs from RAM, so the boot card can be swapped for any FAT microSD
after start-up; mdev mounts its first partition at /mnt/microsd with "sync".
The file is the binary PSBT (BIP174), which Sparrow/Shrike/Electrum open
directly. Names never overwrite: signed-<txid prefix>.psbt, then -2, -3...
"""
import os

from embit.psbt import PSBT


def export_dir() -> str:
    from seedsigner.hardware.microsd import MicroSD
    from seedsigner.models.settings import Settings

    if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
        if not MicroSD.get_instance().is_inserted:
            raise OSError("no microSD card")
        return MicroSD.MOUNT_POINT
    # Raspberry Pi OS / simulator: the working directory stands in for the card.
    return os.getcwd()


def signed_filename(psbt: PSBT, existing) -> str:
    base = "signed-" + psbt.tx.txid().hex()[:12]
    name = base + ".psbt"
    n = 2
    while name in existing:
        name = f"{base}-{n}.psbt"
        n += 1
    return name


def save_signed_psbt(psbt: PSBT, directory: str = None) -> str:
    directory = directory or export_dir()
    name = signed_filename(psbt, set(os.listdir(directory)))
    path = os.path.join(directory, name)
    data = psbt.serialize()
    with open(path, "xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    # Read it back: a card pulled out too early or a full card must not pass.
    with open(path, "rb") as f:
        if f.read() != data:
            raise OSError("written file does not match")
    return name
