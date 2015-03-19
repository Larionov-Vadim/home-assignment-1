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


def target_fake_func(args):
    pass


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


    def test_load_config_from_pyfile_positive_test(self):
        config_mock = Mock()
        execfile_mock = Mock(side_effect=execfile_fake_for_correct)
        with patch('source.lib.utils.Config', config_mock), \
             patch('__builtin__.execfile', execfile_mock):
            return_cfg = utils.load_config_from_pyfile('filepath')
        self.assertEqual(return_cfg.KEY, 'value')

    def test_load_config_from_pyfile_negative_test(self):
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
            actual_result = utils.check_network_status('check_utl', 3)
            self.assertTrue(actual_result)

    def test_check_network_status_URLError(self):
        with patch('urllib2.urlopen', Mock(side_effect=URLError('Test exception'))):
            actual_result = utils.check_network_status('check_utl', 3)
            self.assertFalse(actual_result)

    def test_check_network_status_raise_socket_error_exception(self):
        with patch('urllib2.urlopen', Mock(side_effect=socket.error)):
            actual_result = utils.check_network_status('check_utl', 3)
            self.assertFalse(actual_result)

    def test_check_network_status_raise_ValueError_exception(self):
        with patch('urllib2.urlopen', Mock(side_effect=ValueError)):
            actual_result = utils.check_network_status('check_utl', 3)
            self.assertFalse(actual_result)



    def test_parse_cmd_args_with_config(self):
        args = ['--config', './config']
        parser = utils.parse_cmd_args(args)
        self.assertEqual(parser.config, './config',)
        self.assertIsNone(parser.pidfile)
        self.assertFalse(parser.daemon)

    def test_parse_cmd_args_without_config(self):
        with self.assertRaises(SystemExit):
            utils.parse_cmd_args([])
        self.assertTrue(exit)

    def test_parse_cmd_args_check_add_daemon_argument(self):
        args = ['--config', './config',
                 '--pid', './pidfile',
                 '--daemon']
        parser = utils.parse_cmd_args(args)
        self.assertEqual(parser.config, './config')
        self.assertEqual(parser.pidfile, './pidfile')
        self.assertTrue(parser.daemon)

    def test_parse_cmd_args_check_add_pidfile(self):
        args = ['--config', './config',
                 '--pid', './pidfile']
        parser = utils.parse_cmd_args(args)
        self.assertEqual(parser.config, './config')
        self.assertEqual(parser.pidfile, './pidfile')
        self.assertFalse(parser.daemon)


    def test_spawn_workers_check_set_params(self):
        parent_pid = 132
        Process_mock = Mock()
        with patch('source.lib.utils.Process', Process_mock):
            utils.spawn_workers(1, target_fake_func, [], parent_pid)
        Process_mock.assert_called_once_with(
            target=target_fake_func,
            args=[],
            kwargs={'parent_pid': parent_pid}
        )

    def test_spawn_workers_with_one_iteration(self):
        p_mock = Mock()
        with patch('source.lib.utils.Process', mock.Mock(return_value=p_mock)):
            utils.spawn_workers(1, target_fake_func, [], parent_pid=102)
        self.assertTrue(p_mock.daemon)
        p_mock.start.assert_called_once_with()

    def test_spawn_workers_with_more_then_one_iteration(self):
        p_mock = Mock()
        with patch('source.lib.utils.Process', mock.Mock(return_value=p_mock)):
            utils.spawn_workers(4, target_fake_func, [], parent_pid=102)
        self.assertEqual(p_mock.start.call_count, 4)


    def test_get_tube_set_args(self):
        fake_space = 7
        tarantool_queue_mock = Mock()
        with patch('source.lib.utils.tarantool_queue', tarantool_queue_mock):
            utils.get_tube('fake_host', 8080, fake_space, 'fake_name')
        tarantool_queue_mock.Queue.assert_called_once_with(
            host='fake_host',
            port=8080,
            space=fake_space
        )

    def test_get_tube__tube_has_been_called(self):
        fake_space = 0
        queue_mock = Mock()
        with patch('source.lib.utils.tarantool_queue.Queue', Mock(return_value=queue_mock)):
            utils.get_tube('host', 8080, fake_space, 'name')
        queue_mock.tube.assert_called_once_with('name')
