import pytest
import responses

from matrix_client.api import MATRIX_V2_API_PATH
from matrix_client.client import MatrixClient
from matrix_client.errors import MatrixRequestError
from matrix_client.device import Device

HOSTNAME = 'http://localhost'


class TestDevice(object):

    cli = MatrixClient(HOSTNAME)
    user_id = '@test:localhost'
    device_id = 'AUIETRSN'

    @pytest.fixture()
    def device(self):
        return Device(self.cli.api, self.user_id, self.device_id)

    @responses.activate
    def test_get_info(self, device):
        device_url = HOSTNAME + MATRIX_V2_API_PATH + '/devices/' + self.device_id
        display_name = 'android'
        last_seen_ip = '1.2.3.4'
        last_seen_ts = 1474491775024
        resp = {
            "device_id": self.device_id,
            "display_name": display_name,
            "last_seen_ip": last_seen_ip,
            "last_seen_ts": last_seen_ts
        }
        responses.add(responses.GET, device_url, json=resp)

        assert device.get_info()
        assert device.display_name == display_name
        assert device.last_seen_ip == last_seen_ip
        assert device.last_seen_ts == last_seen_ts

        responses.replace(responses.GET, device_url, status=404)
        assert not device.get_info()

        responses.replace(responses.GET, device_url, status=500)
        with pytest.raises(MatrixRequestError):
            device.get_info()
