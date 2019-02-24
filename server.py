"""
    server.py

    Name: Sean Walker
    NetID: skw34

    CPSC 310, Spring 2019
    Homework 2

    Implements a secure electronic election server.
"""

import cgi
from collections import Counter
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer

import vote_crypto


HOSTNAME = "localhost"

# maximum number of votes (in total) allowed in the election
# -1 indicates arbitarily many, and is used by default
# for hw2, the simulation takes only 2 votes; this is set by a parameter to
# the server class (if it is not provided, then it defaults to this constant)
NUM_VOTES_UNTIL_QUIT = -1
PORT = 9001

has_cast_vote = []
vote_tally = Counter()


class ElectionHTTPHandler(BaseHTTPRequestHandler):
    def __init__(self, private_key, voter_registry, *args, **kwargs):
        # NOTE: credit to mtraceur's answer at
        # https://stackoverflow.com/a/52046062 for inpsiration for this design
        # BaseHTTPRequestHandler calls do_GET **inside** __init__ !!!
        # so we have to call super().__init__ after setting attributes.
        self.private_key = private_key
        self.voter_registry = voter_registry
        super().__init__(*args, **kwargs)

    def do_POST(self):
        # ensure proper usage
        if self.path != "/":
            self.send_error(400, "Invalid endpoint requested")
            return

        # attempt to extract client's encrypted vote
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ={"REQUEST_METHOD": "POST"})
        message = form.getvalue("encrypted_vote")
        if not message:
            self.send_error(400, "Invalid request parameters received")
            return

        # attempt to decrypt message
        (encrypted_vote, signature) = vote_crypto.decode(message)
        (voter_id, candidate_choice, voter_token) = vote_crypto.decrypt(
            self.private_key, encrypted_vote)

        print(
            f"vote: {voter_id} with token {voter_token} voted for {candidate_choice}")

        # verify this vote is valid
        if not self.voter_registry.get(voter_id) or voter_id in has_cast_vote:
            # voter is not registered or has already cast a vote: this vote
            # is invalid
            self.send_error(403, "Vote not allowed")
            return

        # tally the verified vote
        vote_tally[candidate_choice] += 1
        has_cast_vote.append(voter_id)

        # headers
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.send_header("content-encoding", "utf-8")
        self.end_headers()

        # content
        self.wfile.write(
            bytes("Vote received and tallied. Thank you for participating.",
                  "UTF-8"))
        return


class ElectionServer():
    def __init__(self, private_key, voter_registry,
                 num_votes_until_quit=NUM_VOTES_UNTIL_QUIT):
        self.private_key = private_key
        self.voter_registry = voter_registry
        self.num_votes_until_quit = num_votes_until_quit
        self.num_served_votes = 0

    def start(self):
        handler = partial(ElectionHTTPHandler,
                          self.private_key, self.voter_registry)
        httpd = HTTPServer((HOSTNAME, PORT), handler)

        # run server
        print(
            f"election server starting... listening at {HOSTNAME}:{PORT}")
        while self.num_served_votes != self.num_votes_until_quit:
            httpd.handle_request()
            self.num_served_votes += 1
            print(self.num_served_votes)
        print("election server stopping...")
        httpd.server_close()
        print("server stopped. election is complete.")
        print(f"election results (total of {self.num_served_votes} received):")

        # print results of election to server's terminal
        for candidate, num_votes in vote_tally.most_common():
            print(f"- {candidate} received {num_votes} vote(s)")


if __name__ == "__main__":
    server = ElectionServer(vote_crypto.client2["private_key"], {
                            "v1234": vote_crypto.client1["public_key"]})
    server.start()
