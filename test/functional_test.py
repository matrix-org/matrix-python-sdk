import os
import vcr
import unittest

from matrix_client.client import MatrixClient

FILE_DIR = os.path.dirname(__file__)

my_vcr = vcr.VCR(
    cassette_library_dir=os.path.join(FILE_DIR, "recordings"),
    record_mode="new_episodes",
)


class TestFunctional(unittest.TestCase):

    def setUp(self):
        pass

    @my_vcr.use_cassette()
    def test_token(self):
        client = MatrixClient("https://matrix.org")
        # guest user
        token = client.register_as_guest()
        self.assertTrue(token)

    @my_vcr.use_cassette()
    def test_get_rooms(self):
        client = MatrixClient("https://matrix.org")
        client.register_as_guest()
        rooms = client.get_rooms()
        self.assertEqual(len(rooms), 0)
