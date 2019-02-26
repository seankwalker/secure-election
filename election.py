import vote_crypto
"""
    election.py

    Name: Sean Walker
    NetID: skw34

    CPSC 310, Spring 2019
    Homework 2

    Uses client and server implementations to simulate a secure election.
"""


import secrets
import threading

from client import VoterClient
from server import ElectionServer, HOSTNAME as server_hostname, \
    PORT as server_port


def main():
    # define election service parameters:
    # server URL and port
    server = {
        "url": "http://" + server_hostname,
        "port": str(server_port)
    }

    # define voter parameters:
    # each voter has (and knows) their own id, choice of candidate, and
    # random token
    voter1 = {
        "id": "1",
        "candidate": "Samuel Judson",
        "token": secrets.token_hex(16)
    }
    voter2 = {
        "id": "2",
        "candidate": "Joan Feigenbaum",
        "token": secrets.token_hex(16)
    }

    # define voter registry: mapping of voter ids to their public keys
    # (known by election service)
    voter_registry = {
        voter1["id"]: vote_crypto.client1["public_key"],
        voter2["id"]: vote_crypto.client2["public_key"]
    }

    # define voter random token registry: mapping of voter ids to their tokens
    # for _this_ election only (known by election service)
    voter_tokens = {
        voter1["id"]: voter1["token"],
        voter2["id"]: voter2["token"]
    }

    # instantiate election server and voter clients
    election_server = ElectionServer(
        vote_crypto.server["private_key"], voter_registry, voter_tokens,
        num_votes_until_quit=2)
    voter_client1 = VoterClient(
        vote_crypto.client1["private_key"], voter1["id"], voter1["token"],
        server["url"], server["port"])
    voter_client2 = VoterClient(
        vote_crypto.client2["private_key"], voter2["id"], voter2["token"],
        server["url"], server["port"])

    server_thread = threading.Thread(target=election_server.start)
    voter_thread1 = threading.Thread(target=voter_client1.cast_vote, args=(
        vote_crypto.server["public_key"], voter1["candidate"]))
    voter_thread2 = threading.Thread(target=voter_client2.cast_vote, args=(
        vote_crypto.server["public_key"], voter2["candidate"]))

    server_thread.start()
    voter_thread1.start()
    voter_thread2.start()

    # wait for threads to complete
    voter_thread1.join()
    voter_thread2.join()
    server_thread.join()


if __name__ == "__main__":
    main()
