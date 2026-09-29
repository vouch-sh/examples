import os

# The agent reads its resource identifier at import time. TestClient sends requests
# to http://testserver, so that is the origin the tokens and proofs are minted for.
os.environ["VOUCH_AUDIENCE"] = "http://testserver"
