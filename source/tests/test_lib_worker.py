import unittest
import mock
from mock import patch
from source.lib import worker

class WorkerTestCase(unittest.TestCase):

    def test_get_redirect_history_from_task_error_in_history_and_is_not_recheck(self):
        timeout = 1
        url = 'url'
        is_input = True
        mock_task = mock.Mock()
        mock_task.data = {
            'recheck': False,
            'url': 'url',
            'url_id': 0
        }
        mock_get_redirect_history = mock.Mock(return_value=[['ERROR'], [], []])
        with patch('source.lib.worker.get_redirect_history', mock_get_redirect_history),\
             patch('source.lib.worker.to_unicode', mock.Mock(return_value=url)):
            waiting_result = (is_input, mock_task.data)
            result = worker.get_redirect_history_from_task(mock_task, timeout)
            self.assertEqual(result, waiting_result)

    #maybe it is unnecessary
    def test_get_redirect_history_from_task_error_not_in_history_and_is_not_recheck(self):
        timeout = 1
        url = 'url'
        is_input = False
        mock_task = mock.Mock()
        mock_task.data = {
            'recheck': False,
            'url': 'url',
            'url_id': 0
        }
        mock_get_redirect_history = mock.Mock(return_value=[['smf else'],[],[]])
        with patch('source.lib.worker.get_redirect_history', mock_get_redirect_history),\
             patch('source.lib.worker.to_unicode', mock.Mock(return_value=url)):
            waiting_result = (is_input, {
                "url_id": mock_task.data["url_id"],
                "result": [['smf else'],[],[]],
                "check_type": "normal"
            })
            result = worker.get_redirect_history_from_task(mock_task, timeout)
            self.assertEqual(result, waiting_result)

    def test_get_redirect_history_from_task_error_not_in_history_and_is_recheck(self):
        timeout = 1
        url = 'url'
        is_input = False
        mock_task = mock.Mock()
        mock_task.data = {
            'recheck': True,
            'url': 'url',
            'url_id': 0
        }
        mock_get_redirect_history = mock.Mock(return_value=[['smf else'],[],[]])
        with patch('source.lib.worker.get_redirect_history', mock_get_redirect_history),\
             patch('source.lib.worker.to_unicode', mock.Mock(return_value=url)):
            waiting_result = (is_input, {
                "url_id": mock_task.data["url_id"],
                "result": [['smf else'],[],[]],
                "check_type": "normal"
            })
            result = worker.get_redirect_history_from_task(mock_task, timeout)
            self.assertEqual(result, waiting_result)