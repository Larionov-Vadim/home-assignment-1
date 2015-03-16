# -*- coding: utf-8 -*-
import unittest
import mock
from source import notification_pusher
import signal

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


signums = list()
def stop_handler_fake(signum):
    signums.append(signum)

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
        os_fork_mock = mock.Mock(side_effect=OSError(0, 'Boom!'))
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
