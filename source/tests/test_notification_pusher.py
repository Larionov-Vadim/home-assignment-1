# coding: utf-8
import unittest
import mock
import signal
import tarantool
from mock import patch, Mock
from source import notification_pusher
from requests import RequestException
from gevent import queue as gevent_queue
from source.lib.utils import Config


def stop_cycle(self):
    notification_pusher.run_application = False


def execfile_fake_for_correct(filepath, variables):
    variables['KEY'] = 'value'


def execfile_fake_for_incorrect(filepath, variables):
    variables['key'] = 'VALUE'
    variables['Key'] = 'Value'
    variables['kEY'] = 'value'
    variables['_KEY'] = '_value'


config = Config()
config = mock.Mock()
config.QUEUE_HOST = 'localhost'
config.QUEUE_PORT = 31
config.QUEUE_SPACE = 0
config.WORKER_POOL_SIZE = 4
config.QUEUE_TAKE_TIMEOUT = 1
config.SLEEP_ON_FAIL = 0
config.SLEEP = 1


class NotificationPusherTestCase(unittest.TestCase):
    def test_create_pidfile(self):
        pid = 42
        m_open = mock.mock_open()
        with patch('source.notification_pusher.open', m_open, create=True):
            with mock.patch('os.getpid', mock.Mock(return_value=pid)):
                notification_pusher.create_pidfile('/file/path')

        m_open.assert_called_once_with('/file/path', 'w')
        m_open().write.assert_called_once_with(str(pid))


    def test_daemonize_pid_not_zero(self):
        os_exit_mock = Mock()
        pid = 139  # pid != 0
        with patch('os.fork', mock.Mock(return_value=pid)), \
             patch('os._exit', os_exit_mock ):
            notification_pusher.daemonize()
        os_exit_mock.assert_called_once_with(0)

    def test_daemonize_pid_zero_then_not_zero(self):
        pid = [0, 724]  # pid == 0 and pid != 0
        os_exit_mock = Mock()
        with patch('os.fork', Mock(side_effect=pid)), \
             patch('os._exit', os_exit_mock), \
             patch('os.setsid', mock.Mock()):
            notification_pusher.daemonize()
        os_exit_mock.assert_called_once_with(0)

    def test_daemonize_pid_always_zero(self):
        pid = 0   # pid is always zero
        with patch('os.fork', Mock(return_value=pid)), \
             patch('os._exit', Mock()), \
             patch('os.setsid', mock.Mock()):
            self.assertRaises(Exception, notification_pusher.daemonize)

    def test_daemonize_raise_os_error_exception(self):
        os_fork_mock = Mock(side_effect=OSError(0, 'Test exception'))
        with patch('os.fork', os_fork_mock, create=True):
            self.assertRaises(Exception, notification_pusher.daemonize)

    def test_daemonize_pid_zero_then_raise_os_error_exception(self):
        os_fork_mock = Mock(side_effect=[0, OSError(0, 'Test exception')])
        with patch('os.fork', os_fork_mock, create=True), \
             patch('os.setsid', Mock(), create=True):
            self.assertRaises(Exception, notification_pusher.daemonize)


    def test_load_config_from_pyfile_correct(self):
        config_mock = Mock()
        execfile_mock = Mock(side_effect=execfile_fake_for_correct)
        with patch('source.notification_pusher.Config', config_mock), \
             patch('__builtin__.execfile', execfile_mock):
            return_cfg = notification_pusher.load_config_from_pyfile('filepath')
        self.assertEqual(return_cfg.KEY, 'value')

    def test_load_config_from_pyfile_uncorrect(self):
        execfile_mock = Mock(side_effect=execfile_fake_for_incorrect)
        with patch('source.notification_pusher.Config', Mock()), \
             patch('__builtin__.execfile', execfile_mock):
            return_cfg = notification_pusher.load_config_from_pyfile('filepath')
        self.assertNotEqual(return_cfg.key, 'VALUE')
        self.assertNotEqual(return_cfg.Key, 'value')
        self.assertNotEqual(return_cfg.kEY, 'value')
        self.assertNotEqual(return_cfg._KEY, 'value')


    def test_notification_worker(self):
        task_mock = mock.MagicMock()
        task_queue_mock = Mock()
        with patch('requests.post', Mock()), \
             patch('json.dumps', Mock()), \
             patch('source.notification_pusher.logger', Mock()):
            notification_pusher.notification_worker(task_mock, task_queue_mock)
        task_queue_mock.put.assert_called_once_with((task_mock, 'ack'))

    def test_notification_worker_with_request_exception(self):
        task_mock = mock.MagicMock()
        task_queue_mock = mock.Mock()
        with patch('requests.post', mock.Mock(side_effect=RequestException('Test exception'))), \
             patch('json.dumps', mock.Mock()), \
             patch('source.notification_pusher.logger', Mock()):
            notification_pusher.notification_worker(task_mock, task_queue_mock)
        task_queue_mock.put.assert_called_once_with((task_mock, 'bury'))


    def test_done_with_processed_tasks_empty_queue_raise_exception(self):
        task_queue_mock = Mock()
        task_queue_mock.qsize.return_value = 1
        task_queue_mock.get_nowait.side_effect = gevent_queue.Empty('Test exception')
        with patch('source.notification_pusher.logger', Mock()):
            self.assertRaises(gevent_queue.Empty, notification_pusher.done_with_processed_tasks(task_queue_mock))

    def test_done_with_processed_tasks_qsize_zero(self):
        task_queue_mock = mock.Mock()
        task_queue_mock.qsize.return_value = 0
        logger_mock = Mock()
        with patch('source.notification_pusher.logger', logger_mock):
            notification_pusher.done_with_processed_tasks(task_queue_mock)
        self.assertEqual(logger_mock.debug.call_count, 1)

    def test_done_with_processed_tasks_correct(self):
        task_mock = Mock()
        task_queue_mock = Mock()
        task_queue_mock.qsize.return_value = 1
        task_queue_mock.get_nowait.side_effect = lambda: (task_mock, 'fake_action')
        with patch('source.notification_pusher.logger', Mock()):
            notification_pusher.done_with_processed_tasks(task_queue_mock)
        task_mock.fake_action.assert_called_once_with()

    def test_done_with_processed_tasks_raise_tarantool_databaseerror_exception(self):
        task_mock = Mock()
        task_mock.fake_action.side_effect = tarantool.DatabaseError('AAA')
        task_queue_mock = Mock()
        task_queue_mock.qsize.return_value = 1
        task_queue_mock.get_nowait.side_effect = lambda: (task_mock, 'fake_action')
        with patch('source.notification_pusher.logger', Mock()):
            self.assertRaises(tarantool.DatabaseError, notification_pusher.done_with_processed_tasks(task_queue_mock))


    def test_install_signal_handlers(self):
        gevent_mock = Mock()
        with patch('gevent.signal', gevent_mock):
            notification_pusher.install_signal_handlers()
        stop_handler = notification_pusher.stop_handler
        gevent_mock.assert_any_call(signal.SIGTERM, stop_handler, signal.SIGTERM)
        gevent_mock.assert_any_call(signal.SIGINT, stop_handler, signal.SIGINT)
        gevent_mock.assert_any_call(signal.SIGHUP, stop_handler, signal.SIGHUP)
        gevent_mock.assert_any_call(signal.SIGQUIT, stop_handler, signal.SIGQUIT)


    def test_parse_cmd_args_check_add_requared_config_argument(self):
        args = ['--config', './config']
        parser_mock = Mock()
        argparse_mock = Mock()
        argparse_mock.ArgumentParser.return_value = parser_mock
        with patch('source.notification_pusher.argparse', argparse_mock):
            notification_pusher.parse_cmd_args(args=args)
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
        with patch('source.notification_pusher.argparse', argparse_mock):
            notification_pusher.parse_cmd_args(args=args)
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
        with patch('source.notification_pusher.argparse', argparse_mock):
            notification_pusher.parse_cmd_args(args=args)
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
        with patch('source.notification_pusher.argparse', argparse_mock):
            notification_pusher.parse_cmd_args(args=args)
        parser_mock.parse_args.assert_called_once_with(args=args)


    def test_stop_handler(self):
        signum = 100
        offset = 128
        with patch('source.notification_pusher.logger', Mock()):
            notification_pusher.stop_handler(signum)
        exit_code = notification_pusher.exit_code
        run_application = notification_pusher.run_application
        self.assertFalse(run_application)
        self.assertEqual(exit_code, signum + offset)


    def test_main_with_uncorrect_tupe_of_parametr(self):
        uncorrect_args = 100
        with self.assertRaises(TypeError):
            notification_pusher.main(uncorrect_args)

    def test_main_check_is_daemon_and_pidfile(self):
        args = mock.MagicMock()
        args.daemon = True
        args.pidfile = True
        exit_code = 0
        mock_load_config_from_pyfile = mock.Mock(return_value=config)
        mock_parse_cmd_args = mock.Mock(return_value=args)
        mock_daemonize = mock.Mock()
        mock_create_pidfile = mock.Mock()
        mock_stop_cycle = mock.Mock(side_effect=stop_cycle)
        with patch('source.notification_pusher.parse_cmd_args', mock_parse_cmd_args),\
             patch('source.notification_pusher.daemonize', mock_daemonize),\
             patch('source.notification_pusher.create_pidfile', mock_create_pidfile),\
             patch('source.notification_pusher.load_config_from_pyfile', mock_load_config_from_pyfile),\
             patch('source.notification_pusher.patch_all', mock.Mock()),\
             patch('source.notification_pusher.install_signal_handlers', mock.Mock()),\
             patch('source.notification_pusher.dictConfig', mock.Mock()),\
             patch('source.notification_pusher.main_loop', mock.Mock(side_effect=mock_stop_cycle)),\
             patch('source.notification_pusher.os.path.realpath', mock.Mock()),\
             patch('source.notification_pusher.os.path.expanduser', mock.Mock()),\
             patch('source.notification_pusher.sleep', mock_stop_cycle):
            return_exitcode = notification_pusher.main(args)
            self.assertEqual(return_exitcode, exit_code)
            self.assertTrue(mock_daemonize.assert_called)
            self.assertTrue(mock_create_pidfile.assert_called)
            notification_pusher.run_application = True

    def test_main_check_args_is_not_daemon_and_pidfile(self):
        args = mock.MagicMock()
        args.daemon = False
        args.pidfile = False
        exit_code = 0
        mock_load_config_from_pyfile = mock.Mock(return_value=config)
        mock_parse_cmd_args = mock.Mock(return_value=args)
        mock_daemonize = mock.Mock()
        mock_create_pidfile = mock.Mock()
        mock_stop_cycle = mock.Mock(side_effect=stop_cycle)
        with patch('source.notification_pusher.parse_cmd_args', mock_parse_cmd_args),\
             patch('source.notification_pusher.daemonize', mock_daemonize),\
             patch('source.notification_pusher.create_pidfile', mock_create_pidfile),\
             patch('source.notification_pusher.load_config_from_pyfile', mock_load_config_from_pyfile),\
             patch('source.notification_pusher.patch_all', mock.Mock()),\
             patch('source.notification_pusher.install_signal_handlers', mock.Mock()),\
             patch('source.notification_pusher.dictConfig', mock.Mock()),\
             patch('source.notification_pusher.main_loop', mock.Mock(side_effect=mock_stop_cycle)),\
             patch('source.notification_pusher.os.path.realpath', mock.Mock()),\
             patch('source.notification_pusher.os.path.expanduser', mock.Mock()),\
             patch('source.notification_pusher.sleep', mock_stop_cycle):
            return_exitcode = notification_pusher.main(args)
            self.assertEqual(return_exitcode, exit_code)
            self.assertEqual(mock_daemonize.call_count, 0)
            self.assertEqual(mock_create_pidfile.call_count, 0)
            notification_pusher.run_application = True

    def test_main_main_loop_bad(self):
        args = mock.MagicMock()
        args.daemon = False
        args.pidfile = False
        exit_code = 0
        mock_load_config_from_pyfile = mock.Mock(return_value=config)
        mock_parse_cmd_args = mock.Mock(return_value=args)
        mock_stop_cycle = mock.Mock(side_effect=stop_cycle)
        with patch('source.notification_pusher.parse_cmd_args', mock_parse_cmd_args),\
             patch('source.notification_pusher.load_config_from_pyfile', mock_load_config_from_pyfile),\
             patch('source.notification_pusher.patch_all', mock.Mock()),\
             patch('source.notification_pusher.install_signal_handlers', mock.Mock()),\
             patch('source.notification_pusher.dictConfig', mock.Mock()),\
             patch('source.notification_pusher.main_loop', mock.Mock(side_effect=Exception)),\
             patch('source.notification_pusher.os.path.realpath', mock.Mock()),\
             patch('source.notification_pusher.os.path.expanduser', mock.Mock()),\
             patch('source.notification_pusher.sleep', mock_stop_cycle),\
             patch('source.notification_pusher.logger', Mock()):
            return_exitcode = notification_pusher.main(args)
            self.assertEqual(return_exitcode, exit_code)
            self.assertRaises(Exception)
            notification_pusher.run_application = True


    def test_main_loop_with_uncorrect_tupe_of_parametr(self):
        uncorrect_config = 'everything bad'
        with self.assertRaises(AttributeError):
            notification_pusher.main_loop(uncorrect_config)

    def test_main_loop_no_free_workers_count(self):
        config.WORKER_POOL_SIZE = 0
        mock_take = mock.Mock()
        mock_stop_cycle = mock.Mock(side_effect=stop_cycle)
        with patch('source.notification_pusher.sleep', mock_stop_cycle),\
             patch('tarantool_queue.tarantool_queue.Tube.take', mock_take):
            notification_pusher.main_loop(config)
            self.assertFalse(mock_take.called)
            notification_pusher.run_application = True

    def test_main_loop_with_free_workers_count_and_task_ok(self):
        config.WORKER_POOL_SIZE = 4
        mock_take = mock.Mock()
        mock_greenlet = mock.MagicMock()
        mock_stop_cycle = mock.Mock(side_effect=stop_cycle)
        with patch('source.notification_pusher.sleep', mock_stop_cycle),\
             patch('source.notification_pusher.Greenlet', mock_greenlet),\
             patch('tarantool_queue.tarantool_queue.Tube.take', mock_take):
            notification_pusher.main_loop(config)
            self.assertTrue(mock_greenlet.called)
            notification_pusher.run_application = True

    def test_main_loop_with_free_workers_count_and_task_bad(self):
        config.WORKER_POOL_SIZE = 4
        mock_take = mock.Mock(return_value=False)
        mock_greenlet = mock.MagicMock()
        mock_stop_cycle = mock.Mock(side_effect=stop_cycle)
        with patch('source.notification_pusher.sleep', mock_stop_cycle),\
             patch('source.notification_pusher.Greenlet', mock_greenlet),\
             patch('tarantool_queue.tarantool_queue.Tube.take', mock_take):
            notification_pusher.main_loop(config)
            self.assertFalse(mock_greenlet.called)
            notification_pusher.run_application = True
