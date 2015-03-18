# coding: utf-8
import unittest
import mock
import socket
from source.lib import utils
from urllib2 import URLError
from mock import patch, Mock


def execfile_fake_for_correct(filepath, variables):
    variables['KEY'] = 'value'


def execfile_fake_for_incorrect(filepath, variables):
    variables['key'] = 'VALUE'
    variables['Key'] = 'Value'
    variables['kEY'] = 'value'
    variables['_KEY'] = '_value'


class UtilsTestCase(unittest.TestCase):
    def test_daemonize_pid_not_zero(self):
        os_exit_mock = Mock()
        pid = 127           # pid != 0
        with patch('os.fork', Mock(return_value=pid)), \
             patch('os._exit', os_exit_mock, create=True):
            utils.daemonize()
        os_exit_mock.assert_called_once_with(0)

    def test_daemonize_pid_zero_then_not_zero(self):
        pid = [0, 630]      # pid == 0 and pid != 0
        os_exit_mock = Mock()
        with patch('os.fork', Mock(side_effect=pid)), \
             patch('os._exit', os_exit_mock), \
             patch('os.setsid', mock.Mock()):
            utils.daemonize()
        os_exit_mock.assert_called_once_with(0)

    def test_daemonize_pid_always_zero(self):
        os_exit_mock = Mock()
        pid = 0                 # pid is always zero
        with patch('os.fork', Mock(return_value=pid)), \
             patch('os._exit', os_exit_mock), \
             patch('os.setsid', mock.Mock()):
            self.assertRaises(Exception, utils.daemonize)

    def test_daemonize_raise_os_error_exception(self):
        os_fork_mock = Mock(side_effect=OSError(0, 'Test exception'))
        with patch('os.fork', os_fork_mock):
            self.assertRaises(Exception, utils.daemonize)

    def test_daemonize_pid_zero_then_raise_os_error_exception(self):
        os_fork_mock = Mock(side_effect=[0, OSError(0, 'Test exception')])
        with patch('os.fork', os_fork_mock), \
             patch('os.setsid', Mock()):
            self.assertRaises(Exception, utils.daemonize)


    def test_create_pidfile(self):
        pid = 42
        m_open = mock.mock_open()
        with patch('source.lib.utils.open', m_open, create=True), \
             patch('os.getpid', mock.Mock(return_value=pid)):
                utils.create_pidfile('/file/path')
        m_open.assert_called_once_with('/file/path', 'w')
        m_open().write.assert_called_once_with(str(pid))


    def test_load_config_from_pyfile_correct(self):
        config_mock = Mock()
        execfile_mock = Mock(side_effect=execfile_fake_for_correct)
        with patch('source.lib.utils.Config', config_mock), \
             patch('__builtin__.execfile', execfile_mock):
            return_cfg = utils.load_config_from_pyfile('filepath')
        self.assertEqual(return_cfg.KEY, 'value')

    def test_load_config_from_pyfile_uncorrect(self):
        config_mock = Mock()
        execfile_mock = Mock(side_effect=execfile_fake_for_incorrect)
        with patch('source.lib.utils.Config', config_mock), \
             patch('__builtin__.execfile', execfile_mock):
            return_cfg = utils.load_config_from_pyfile('filepath')
        self.assertNotEqual(return_cfg.key, 'VALUE')
        self.assertNotEqual(return_cfg.Key, 'value')
        self.assertNotEqual(return_cfg.kEY, 'value')
        self.assertNotEqual(return_cfg._KEY, 'value')


    def test_check_network_status_correct(self):
        with patch('urllib2.urlopen', Mock):
            return_value = utils.check_network_status('check_utl', 3)
            self.assertTrue(return_value)

    def test_check_network_status_URLError(self):
        with patch('urllib2.urlopen', Mock(side_effect=URLError('Test exception'))):
            return_value = utils.check_network_status('check_utl', 3)
            self.assertFalse(return_value)

    def test_check_network_status_raise_socket_error_exception(self):
        with patch('urllib2.urlopen', Mock(side_effect=socket.error)):
            return_value = utils.check_network_status('check_utl', 3)
            self.assertFalse(return_value)

    def test_check_network_status_raise_ValueError_exception(self):
        with patch('urllib2.urlopen', Mock(side_effect=ValueError)):
            return_value = utils.check_network_status('check_utl', 3)
            self.assertFalse(return_value)


    def test_parse_cmd_args_check_add_requared_config_argument(self):
        args = ['--config', './config']
        parser_mock = Mock()
        argparse_mock = Mock()
        argparse_mock.ArgumentParser.return_value = parser_mock
        with patch('source.lib.utils.argparse', argparse_mock):
            utils.parse_cmd_args(args=args)
        calls = parser_mock.add_argument.call_args_list
        for call in calls:
            args, kwargs = call
            if '-c' in args and kwargs['required']:
                return
        assert False

    def test_parse_cmd_args_check_add_daemon_argument(self):
        args = ['--config', './config',
                '--daemon']
        parser_mock = Mock()
        argparse_mock = Mock()
        argparse_mock.ArgumentParser.return_value = parser_mock
        with patch('source.lib.utils.argparse', argparse_mock):
            utils.parse_cmd_args(args=args)
        calls = parser_mock.add_argument.call_args_list
        for call in calls:
            args, kwargs = call
            if '--daemon' in args:
                return
        assert False

    def test_parse_cmd_args_check_add_pidfile_argument_default(self):
        args = ['--config', './config',
                '--daemon']
        parser_mock = Mock()
        argparse_mock = Mock()
        argparse_mock.ArgumentParser.return_value = parser_mock
        with patch('source.lib.utils.argparse', argparse_mock):
            utils.parse_cmd_args(args=args)
        calls = parser_mock.add_argument.call_args_list
        for call in calls:
            args, kwargs = call
            if '--pid' in args:
                return
        assert False

    def test_parse_cmd_args_check_parse_args_has_been_called(self):
        args = ['--config', './config',
                '--pid', './pidfile']
        parser_mock = Mock()
        argparse_mock = Mock()
        argparse_mock.ArgumentParser.return_value = parser_mock
        with patch('source.lib.utils.argparse', argparse_mock):
            utils.parse_cmd_args(args=args)
        parser_mock.parse_args.assert_called_once_with(args=args)


    def test_spawn_workers(self):
        p_mock = Mock()
        with patch('source.lib.utils.Process', mock.Mock(return_value=p_mock)):
            utils.spawn_workers(1, 'target', [], 0)
        self.assertTrue(p_mock.daemon)
        self.assertEqual(p_mock.start.call_count, 1)


    def test_get_tube__tube_has_been_called(self):
        queue_mock = mock.MagicMock()
        tarantool_queue_mock = Mock(return_value=queue_mock)
        with patch('source.lib.utils.tarantool_queue.Queue', tarantool_queue_mock):
            utils.get_tube('host', 8080, 'space', 'name')
        queue_mock.tube.assert_called_once_with('name')
