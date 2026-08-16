import asyncio
import os
import subprocess
import sys
from typing import Dict

import x3dh
from twomemo import twomemo
import omemo
from omemo.storage import Just, Maybe, JSONType, Nothing

sys.path.insert(0, os.path.abspath("o"))

if sys.argv[1] == "bundle":
    import bundle
    assert len(bundle.ik) == 33
    OMEMO2 = False
elif sys.argv[1] == "bundle2":
    import bundle2 as bundle
    assert len(bundle.ik) == 32
    OMEMO2 = True
else:
    assert False

class StorageImpl(omemo.storage.Storage):
    def __init__(self) -> None:
        super().__init__()
        self.__data: Dict[str, JSONType] = {}

    async def _load(self, key: str) -> Maybe[JSONType]:
        if key in self.__data:
            return Just(self.__data[key])
        return Nothing()

    async def _store(self, key: str, value: JSONType) -> None:
        self.__data[key] = value

    async def _delete(self, key: str) -> None:
        self.__data.pop(key, None)


def run_interop(binary: str, *args: str) -> None:
    command = ["node", binary] if binary.endswith(".cjs") else [binary]
    subprocess.run(command + list(args), check=True)


async def run_oldmemo():
    import xeddsa
    from oldmemo import oldmemo
    ik=xeddsa.curve25519_pub_to_ed25519_pub(oldmemo.StateImpl.parse_public_key(bundle.ik), bool((bundle.spks[63] >> 7) & 1))

    spks=bytearray(bundle.spks)
    spks[63] &= 0x7f
    pks= { oldmemo.StateImpl.parse_public_key(v):k
          for k, v in bundle.pks.items()}
    b=oldmemo.BundleImpl(
        "admin@localhost",7,
        x3dh.Bundle(
            ik,
            oldmemo.StateImpl.parse_public_key(bundle.spk),
            bytes(spks),
            {pk for pk in pks.keys()}
            ),
        bundle.spk_id,
        pks,
    )
    o=oldmemo.Oldmemo(StorageImpl())
    k=oldmemo.PlainKeyMaterialImpl(b"\x55"*16,b"\xaa"*16)
    ses, msg = await o.build_session_active("user@localhost", 8, b, k)
    ser,sign=ses.key_exchange.serialize(msg.serialize())
    with open("o/msg.bin", "wb") as f:
        f.write(ser)

async def run_twomemo():
    pks = { v:k for k, v in bundle.pks.items()}
    b=twomemo.BundleImpl(
        "admin@localhost",7,
        x3dh.Bundle(
            bundle.ik,
            bundle.spk,
            bundle.spks,
            {pk for pk in pks.keys()}
            ),
        bundle.spk_id,
        pks,
    )
    o=twomemo.Twomemo(StorageImpl())
    k=twomemo.PlainKeyMaterialImpl(b"\x55"*32,b"\xaa"*16)
    ses, msg = await o.build_session_active("user@localhost", 8, b, k)
    ser=ses.key_exchange.serialize(msg.serialize())
    with open("o/msg2.bin", "wb") as f:
        f.write(ser)
    if len(sys.argv) == 2:
        return

    interop = sys.argv[2]
    run_interop(
        interop, "initial", "o/msg2.bin", "o/resp2.bin",
        "o/session2.bin"
    )
    with open("o/resp2.bin", "rb") as f:
        response = twomemo.EncryptedKeyMaterialImpl.parse(
            f.read(), "user@localhost", 8
        )
    decrypted = await o.decrypt_key_material(ses, response)
    assert decrypted.key == b"\xcc" * 32
    assert decrypted.auth_tag == b"\x33" * 16

    k=twomemo.PlainKeyMaterialImpl(b"\xdd"*32,b"\x44"*16)
    msg = await o.encrypt_key_material(ses, k)
    with open("o/msg2-next.bin", "wb") as f:
        f.write(msg.serialize())
    run_interop(
        interop, "next", "o/msg2-next.bin", "o/resp2-next.bin",
        "o/session2.bin"
    )
    with open("o/resp2-next.bin", "rb") as f:
        response = twomemo.EncryptedKeyMaterialImpl.parse(
            f.read(), "user@localhost", 8
        )
    decrypted = await o.decrypt_key_material(ses, response)
    assert decrypted.key == b"\xee" * 32
    assert decrypted.auth_tag == b"\x66" * 16
    print("Bidirectional python-twomemo OMEMO 2 interop succeeded")

async def main():
    if OMEMO2:
        await run_twomemo()
    else:
        await run_oldmemo()

asyncio.run(main())
