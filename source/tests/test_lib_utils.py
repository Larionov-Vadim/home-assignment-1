# coding: utf-8
import unittest
import mock
from source.lib import utils
from urllib2 import URLError
import socket


def execfile_fake(filepath, variables):
    variables['KEY'] = 'value'
    variables['key'] = 'VALUE'
    variables['Key'] = 'Value'
    variables['kEY'] = 'value'
    variables['_KEY'] = '_value'


class UtilsTestCase(unittest.TestCase):
    def test_daemonize_pid_not_zero(self):
        os_exit_mock = mock.Mock()
        pid = 127           # pid != 0
        with mock.patch('os.fork', mock.Mock(return_value=pid)), \
             mock.patch('os._exit', os_exit_mock, create=True):
            utils.daemonize()
        os_exit_mock.assert_called_once_with(0)

    def test_daemonize_pid_zero_then_not_zero(self):
        pid = [0, 630]      # pid == 0 and pid != 0
        os_exit_mock = mock.Mock()
        os_fork_mock = mock.Mock()
        os_fork_mock.side_effect = pid

        with mock.patch('os.fork', os_fork_mock), \
             mock.patch('os._exit', os_exit_mock), \
             mock.patch('os.setsid', mock.Mock()):
            utils.daemonize()
        os_exit_mock.assert_called_once_with(0)

    def test_daemonize_pid_always_zero(self):
        os_exit_mock = mock.Mock()
        os_fork_mock = mock.Mock(return_value=0)  # pid is always zero
        with mock.patch('os.fork', os_fork_mock), \
             mock.patch('os._exit', os_exit_mock), \
             mock.patch('os.setsid', mock.Mock()):
            utils.daemonize()
        self.assertEqual(os_exit_mock.call_count, 0)

    def test_daemonize_raise_os_error_exception(self):
        os_fork_mock = mock.Mock(side_effect=OSError(0, 'Test exception'))
        with mock.patch('os.fork', os_fork_mock, create=True):
            self.assertRaises(Exception, utils.daemonize)

    def test_daemonize_pid_zero_then_raise_os_error_exception(self):
        os_fork_mock = mock.Mock(side_effect=[0, OSError(0, 'Test exception')])
        with mock.patch('os.fork', os_fork_mock, create=True), \
             mock.patch('os.setsid', mock.Mock(), create=True):
            self.assertRaises(Exception, utils.daemonize)

    def test_create_pidfile(self):
        pid = 42
        m_open = mock.mock_open()
        with mock.patch('source.lib.utils.open', m_open, create=True):
            with mock.patch('os.getpid', mock.Mock(return_value=pid)):
                utils.create_pidfile('/file/path')

        m_open.assert_called_once_with('/file/path', 'w')
        m_open().write.assert_called_once_with(str(pid))

    # Плохой тест! Разнести по разным тестам стоит
    def test_load_config_from_pyfile(self):
        config_mock = mock.Mock()
        execfile_mock = mock.Mock(side_effect=execfile_fake)
        with mock.patch('source.lib.utils.Config', config_mock), \
             mock.patch('__builtin__.execfile', execfile_mock):
            return_cfg = utils.load_config_from_pyfile('filepath')
        self.assertEqual(return_cfg.KEY, 'value')
        self.assertNotEqual(return_cfg.key, 'VALUE')
        self.assertNotEqual(return_cfg.Key, 'value')
        self.assertNotEqual(return_cfg.kEY, 'value')
        self.assertNotEqual(return_cfg._KEY, 'value')

    # Или не мокать?
    def test_check_network_status_correct(self):
        with mock.patch('urllib2.urlopen', mock.Mock):
            return_value = utils.check_network_status('check_utl', 3)
            self.assertTrue(return_value)

    def test_check_network_status_URLError(self):
        with mock.patch('urllib2.urlopen', mock.Mock(side_effect=URLError('Test exception'))):
            return_value = utils.check_network_status('check_utl', 3)
            self.assertFalse(return_value)

    def test_check_network_status_raise_socket_error_exception(self):
        with mock.patch('urllib2.urlopen', mock.Mock(side_effect=socket.error)):
            return_value = utils.check_network_status('check_utl', 3)
            self.assertFalse(return_value)

    def test_check_network_status_raise_ValueError_exception(self):
        with mock.patch('urllib2.urlopen', mock.Mock(side_effect=ValueError)):
            return_value = utils.check_network_status('check_utl', 3)
            self.assertFalse(return_value)
