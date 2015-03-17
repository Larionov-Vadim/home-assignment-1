# -*- coding: utf-8 -*-
import unittest
import mock
from source import notification_pusher
import signal
from requests import RequestException
from gevent import queue as gevent_queue

config = notification_pusher.Config()
config.QUEUE_HOST = '127.0.0.1'
config.QUEUE_PORT = '8080'
config.QUEUE_SPACE = ''
config.QUEUE_TUBE = ''
config.QUEUE_TAKE_TIMEOUT = ''
config.WORKER_POOL_SIZE = 4
config.SLEEP = 1
config.HTTP_CONNECTION_TIMEOUT = 1


def execfile_fake(filepath, variables):
    variables['KEY'] = 'value'
    variables['key'] = 'VALUE'
    variables['Key'] = 'Value'
    variables['kEY'] = 'value'
    variables['_KEY'] = '_value'


class NotificationPusherTestCase(unittest.TestCase):
    def test_create_pidfile_example(self):
        pid = 42
        m_open = mock.mock_open()
        with mock.patch('source.notification_pusher.open', m_open, create=True):
            with mock.patch('os.getpid', mock.Mock(return_value=pid)):
                notification_pusher.create_pidfile('/file/path')

        m_open.assert_called_once_with('/file/path', 'w')
        m_open().write.assert_called_once_with(str(pid))

    def test_daemonize_pid_not_zero(self):
        os_exit_mock = mock.Mock()
        pid = 139           # pid != 0
        with mock.patch('os.fork', mock.Mock(return_value=pid)), \
             mock.patch('os._exit', os_exit_mock, create=True):
            notification_pusher.daemonize()
        assert os_exit_mock.called

    def test_daemonize_pid_zero_then_not_zero(self):
        pid = [0, 724]      # pid == 0 and pid != 0
        os_exit_mock = mock.Mock()
        os_fork_mock = mock.Mock()
        os_fork_mock.side_effect = pid

        with mock.patch('os.fork', os_fork_mock), \
             mock.patch('os._exit', os_exit_mock), \
             mock.patch('os.setsid', mock.Mock()):
            notification_pusher.daemonize()
        assert os_exit_mock.called

    def test_daemonize_pid_alvays_zero(self):
        os_exit_mock = mock.Mock()
        os_fork_mock = mock.Mock(return_value=0)  # pid is always zero
        with mock.patch('os.fork', os_fork_mock), \
             mock.patch('os._exit', os_exit_mock), \
             mock.patch('os.setsid', mock.Mock()):
            notification_pusher.daemonize()
        self.assertFalse(os_exit_mock.called)

    def test_daemonize_raise_os_error_exception(self):
        os_fork_mock = mock.Mock(side_effect=OSError(0, 'Test exception'))
        with mock.patch('os.fork', os_fork_mock, create=True):
            self.assertRaises(Exception, notification_pusher.daemonize)

    def test_daemonize_pid_zero_then_raise_os_error_exception(self):
        os_fork_mock = mock.Mock(side_effect=[0, OSError(0, 'Boom!')])
        with mock.patch('os.fork', os_fork_mock, create=True), \
             mock.patch('os.setsid', mock.Mock(), create=True):
            self.assertRaises(Exception, notification_pusher.daemonize)

    # Плохой тест! Разнести по разным тестам стоит
    def test_load_config_from_pyfile(self):
        config_mock = mock.Mock()
        execfile_mock = mock.Mock(side_effect=execfile_fake)
        with mock.patch('source.notification_pusher.Config', config_mock), \
             mock.patch('__builtin__.execfile', execfile_mock):
            return_cfg = notification_pusher.load_config_from_pyfile('filepath')
        self.assertEqual(return_cfg.KEY, 'value')
        self.assertNotEqual(return_cfg.key, 'VALUE')
        self.assertNotEqual(return_cfg.Key, 'value')
        self.assertNotEqual(return_cfg.kEY, 'value')
        self.assertNotEqual(return_cfg._KEY, 'value')

    def test_notification_worker(self):
        task_mock = mock.MagicMock()
        task_queue_mock = mock.Mock()

        logger_mock = mock.Mock()
        notification_pusher.logger = logger_mock

        with mock.patch('requests.post', mock.Mock()),\
             mock.patch('json.dumps', mock.Mock()):
            notification_pusher.notification_worker(task_mock, task_queue_mock)

        task_queue_mock.put.assert_called_once_with((task_mock, 'ack'))

    def test_notification_worker_with_request_exception(self):
        task_mock = mock.MagicMock()
        task_queue_mock = mock.Mock()

        logger_mock = mock.Mock()
        notification_pusher.logger = logger_mock

        with mock.patch('requests.post', mock.Mock(side_effect=RequestException('Test exception'))),\
             mock.patch('json.dumps', mock.Mock()):
            notification_pusher.notification_worker(task_mock, task_queue_mock)

        task_queue_mock.put.assert_called_once_with((task_mock, 'bury'))


    # Разве исключение сработает? Цикл ведь проверяет task_queue.qsize() => очередь не пуста
    def test_done_with_processed_tasks_empty_queue_raise_exception(self):
        task_queue_mock = mock.Mock()
        task_queue_mock.qsize.return_value = 1
        task_queue_mock.get_nowait.side_effect = gevent_queue.Empty('Test exception')

        logger_mock = mock.Mock()
        notification_pusher.logger = logger_mock

        self.assertRaises(gevent_queue.Empty, notification_pusher.done_with_processed_tasks(task_queue_mock))

    def test_done_with_processed_tasks_qsize_zero(self):
        task_queue_mock = mock.Mock()
        task_queue_mock.qsize.return_value = 0

        logger_mock = mock.Mock()
        notification_pusher.logger = logger_mock

        notification_pusher.done_with_processed_tasks(task_queue_mock)
        self.assertEqual(logger_mock.debug.call_count, 1)

    """
        Ошибка в getattr_mock()
        RuntimeError: maximum recursion depth exceeded while calling a Python object
    """
    # def test_done_with_processed_tasks(self):
    #     task_mock = mock.Mock()
    #     task_queue_mock = mock.Mock()
    #     task_queue_mock.qsize.return_value = 1
    #     task_queue_mock.get_nowait.side_effect = lambda: (task_mock, 'fake_action_name')
    #
    #     logger_mock = mock.Mock()
    #     notification_pusher.logger = logger_mock
    #
    #     getattr_mock = mock.Mock(side_effect=getattr_fake)
    #     with mock.patch('__builtin__.getattr', getattr_mock):
    #         notification_pusher.done_with_processed_tasks(task_queue_mock)
    #     self.assertEqual(getattr_mock.call_count, 1)






