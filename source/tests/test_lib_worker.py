import unittest
import mock
from mock import patch
from source.lib import worker
from source.lib.utils import Config



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


    def test_get_redirect_history_from_task_is_recheck_and_suspicious_in_data(self):
        timeout = 1
        url = 'url'
        is_input = False
        mock_task = mock.Mock()
        mock_task.data = {
            'recheck': True,
            'url': 'url',
            'url_id': 0,
            'suspicious': 'suspicious'
        }
        mock_get_redirect_history = mock.Mock(return_value=[['ERROR'],[],[]])
        with patch('source.lib.worker.get_redirect_history', mock_get_redirect_history),\
             patch('source.lib.worker.to_unicode', mock.Mock(return_value=url)):
            waiting_result = (is_input, {
                "url_id": mock_task.data["url_id"],
                "result": [['ERROR'],[],[]],
                "check_type": "normal",
                'suspicious':'suspicious'
            })
            result = worker.get_redirect_history_from_task(mock_task, timeout)
            self.assertEqual(result, waiting_result)

    def test_worker_task_path_is_not_exists(self):
        config = mock.MagicMock()
        pid= 31
        path = False
        mock_get_tube = mock.MagicMock()
        mock_get_redirect_history_from_task = mock.Mock()

        with patch('source.lib.worker.os.path.exists', mock.Mock(return_value=path)),\
             patch('source.lib.worker.get_tube', mock_get_tube ),\
             patch('source.lib.worker.get_redirect_history_from_task', mock_get_redirect_history_from_task):
            worker.worker(config, pid)
            self.assertEqual(mock_get_redirect_history_from_task.call_count, 0)

    def test_worker_bad_task(self):
        config = mock.MagicMock()
        pid= 31
        path = True
        tube = mock.MagicMock()
        tube.take = mock.Mock(return_value=None)
        mock_get_tube = mock.Mock(return_value=tube)
        mock_get_redirect_history_from_task = mock.Mock()

        with patch('source.lib.worker.os.path.exists', mock.Mock(side_effect=[True, False])),\
             patch('source.lib.worker.get_tube', mock_get_tube),\
             patch('source.lib.worker.get_redirect_history_from_task', mock_get_redirect_history_from_task):
            worker.worker(config, pid)
            self.assertEqual(mock_get_redirect_history_from_task.call_count, 0)

    def test_worker_task_ok_and_result_bad(self):
        config = mock.MagicMock()
        pid= 31
        # path = True
        mock_input_tube = mock.MagicMock()
        mock_output_tube = mock.MagicMock()
        mock_get_redirect_history_from_task = mock.Mock(return_value=[False, 'data'])

        with patch('source.lib.worker.os.path.exists', mock.Mock(side_effect=[True, False])),\
             patch('source.lib.worker.get_tube', mock.Mock(side_effect=[mock_input_tube, mock_output_tube])),\
             patch('source.lib.worker.get_redirect_history_from_task', mock_get_redirect_history_from_task):
            worker.worker(config, pid)
            self.assertIsNot(mock_get_redirect_history_from_task.call_count, 0)

    def test_worker_task_ok_and_result_ok(self):
        config = mock.MagicMock()
        pid= 31
        # path = True
        mock_input_tube = mock.MagicMock()
        mock_output_tube = mock.MagicMock()
        mock_get_redirect_history_from_task = mock.Mock(return_value=[True, 'data'])

        with patch('source.lib.worker.os.path.exists', mock.Mock(side_effect=[True, False])),\
             patch('source.lib.worker.get_tube', mock.Mock(side_effect=[mock_input_tube, mock_output_tube])),\
             patch('source.lib.worker.get_redirect_history_from_task', mock_get_redirect_history_from_task):
            worker.worker(config, pid)
            self.assertIsNot(mock_get_redirect_history_from_task.call_count, 0)



