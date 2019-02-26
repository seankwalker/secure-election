"""
    client.py

    Name:  Sean Walker
    NetID: skw34

    CPSC 310, Spring 2019
    Homework 2

    Implements a secure electronic election client.
"""

import requests
import secrets

import vote_crypto


class VoterClient:
    def __init__(self, private_key, voter_id, token, election_server_url,
                 election_server_port):
        self.private_key = private_key
        self.voter_id = voter_id
        self.token = token
        self.election_server_url = election_server_url
        self.election_server_port = election_server_port

    def cast_vote(self, public_key, candidate_choice):
        # encrypt vote for candidate under public key of election service
        vote = vote_crypto.encrypt(
            public_key, self.voter_id, candidate_choice, self.token)

        # create digital signature to sign vote
        signature = vote_crypto.sign(self.private_key, vote)

        # sign vote
        message = vote_crypto.encode(vote, signature)
        payload = {"encrypted_vote": message}

        # send vote to server over HTTP
        r = requests.post(self.election_server_url + ":" +
                          self.election_server_port, data=payload)
        print(r.text)


if __name__ == "__main__":
    #     voter = vote_crypto.client1
    #     election_service = vote_crypto.client2
    #     voter_id = "v1234"  # or whatever
    #     voter_token = secrets.token_hex(16)   # random token for vote
    #     voter_candidate_choice = "Rufus T. Firefly"  # or whatever
    #     client = Client(voter["private_key"], voter_id,
    #                     voter_token, "http://localhost", "9001/")
    #     client.cast_vote(election_service["public_key"], voter_candidate_choice)
    voter = vote_crypto.client1
    service = vote_crypto.server
    voter_id = "v1"
    voter_token = secrets.token_hex(16)
    voter_candidate_choice = "Me"
    client = VoterClient(voter["private_key"], voter_id,
                         voter_token, "http://localhost", "9001")
    client.cast_vote(service["public_key"], voter_candidate_choice)
