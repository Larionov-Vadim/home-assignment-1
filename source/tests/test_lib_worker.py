import unittest
import mock
from mock import patch
from source.lib import worker

class WorkerTestCase(unittest.TestCase):

    def test_get_redirect_history_from_task_error_in_histoty_and_is_not_recheck(self):
        timeout = 31
        url = 'url'
        mock_task = mock.Mock()
        mock_task.data = {
            'recheck': False,
            'url': 'url',
            'url_id': 0,
            'suspicious': 'suspicious'
        }
        mock_get_redirect_history = mock.Mock(return_value=[['ERROR']])

        with patch('source.lib.get_redirect_history', mock_get_redirect_history),\
             patch('source.lib.worker.to_unicode', mock.Mock(return_value=url)):

            waiting_result = (True, mock_task.data)
            result = worker.get_redirect_history_from_task(mock_task, timeout)
            self.assertEqual(result, waiting_result)
