import unittest
import mock
from mock import patch
from source.lib.utils import Config
from source import redirect_checker


def stop_cycle(self):
    redirect_checker.loop = False

def start_cycle(self):
    redirect_checker.loop = True

config = Config()
config.CHECK_URL = 'url'
config.HTTP_TIMEOUT = 1
config.WORKER_POOL_SIZE = 4
config.SLEEP = 1

class RedirectCheckerTestCase(unittest.TestCase):

    def test_main_loop_check_network_status_bad(self):
        mock_stop_cycle = mock.Mock(side_effect=stop_cycle)
        mock_check_network_status = mock.Mock(return_value=False)
        mock_spawn_workers = mock.Mock()
        with patch('source.redirect_checker.check_network_status', mock_check_network_status),\
             patch('source.redirect_checker.spawn_workers', mock_spawn_workers),\
             patch('source.redirect_checker.sleep', mock_stop_cycle):
            redirect_checker.main_loop(config)
            self.assertEqual(mock_spawn_workers.call_count, 0)
            redirect_checker.loop = True


