import bittensor as bt
from substrateinterface.base import SubstrateInterface

if __name__ == "__main__":
    substrate = SubstrateInterface(
            ss58_format=bt.__ss58_format__,
            use_remote_preset=True,
            url=f"ws://127.0.0.1:9944",
            type_registry=bt.__type_registry__,
        )

    substrate.websocket.timeout = 30

    # Get the current block from the miner subtensor
    miner_block = substrate.get_block()
    if miner_block != None:
        miner_block = miner_block["header"]["number"]
        print(f"miner_block = {miner_block}")
    else:
        print(f"miner_block = None")