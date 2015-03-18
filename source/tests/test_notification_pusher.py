# coding: utf-8
import unittest
import mock
import signal
from mock import patch
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
config.CHECK_URL = 'url'
config.HTTP_TIMEOUT = 1
config.WORKER_POOL_SIZE = 4
config.SLEEP_ON_FAIL = 1
config.LOGGING = 'logging'
config.EXIT_CODE = 31

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
        pid = 139  # pid != 0
        with mock.patch('os.fork', mock.Mock(return_value=pid)), \
             mock.patch('os._exit', os_exit_mock, create=True):
            notification_pusher.daemonize()
        os_exit_mock.assert_called_once_with(0)

    def test_daemonize_pid_zero_then_not_zero(self):
        pid = [0, 724]  # pid == 0 and pid != 0
        os_exit_mock = mock.Mock()
        os_fork_mock = mock.Mock()
        os_fork_mock.side_effect = pid

        with mock.patch('os.fork', os_fork_mock), \
             mock.patch('os._exit', os_exit_mock), \
             mock.patch('os.setsid', mock.Mock()):
            notification_pusher.daemonize()
        os_exit_mock.assert_called_once_with(0)

    def test_daemonize_pid_always_zero(self):
        os_exit_mock = mock.Mock()
        os_fork_mock = mock.Mock(return_value=0)  # pid is always zero
        with mock.patch('os.fork', os_fork_mock), \
             mock.patch('os._exit', os_exit_mock), \
             mock.patch('os.setsid', mock.Mock()):
            self.assertRaises(Exception, notification_pusher.daemonize)

    def test_daemonize_raise_os_error_exception(self):
        os_fork_mock = mock.Mock(side_effect=OSError(0, 'Test exception'))
        with mock.patch('os.fork', os_fork_mock, create=True):
            self.assertRaises(Exception, notification_pusher.daemonize)

    def test_daemonize_pid_zero_then_raise_os_error_exception(self):
        os_fork_mock = mock.Mock(side_effect=[0, OSError(0, 'Test exception')])
        with mock.patch('os.fork', os_fork_mock, create=True), \
             mock.patch('os.setsid', mock.Mock(), create=True):
            self.assertRaises(Exception, notification_pusher.daemonize)

    def test_load_config_from_pyfile_correct(self):
        config_mock = mock.Mock()
        execfile_mock = mock.Mock(side_effect=execfile_fake_for_correct)
        with mock.patch('source.notification_pusher.Config', config_mock), \
             mock.patch('__builtin__.execfile', execfile_mock):
            return_cfg = notification_pusher.load_config_from_pyfile('filepath')
        self.assertEqual(return_cfg.KEY, 'value')

    def test_load_config_from_pyfile_uncorrect(self):
        config_mock = mock.Mock()
        execfile_mock = mock.Mock(side_effect=execfile_fake_for_incorrect)
        with mock.patch('source.notification_pusher.Config', config_mock), \
             mock.patch('__builtin__.execfile', execfile_mock):
            return_cfg = notification_pusher.load_config_from_pyfile('filepath')
        self.assertNotEqual(return_cfg.key, 'VALUE')
        self.assertNotEqual(return_cfg.Key, 'value')
        self.assertNotEqual(return_cfg.kEY, 'value')
        self.assertNotEqual(return_cfg._KEY, 'value')

    def test_notification_worker(self):
        task_mock = mock.MagicMock()
        task_queue_mock = mock.Mock()

        logger_mock = mock.Mock()
        notification_pusher.logger = logger_mock

        with mock.patch('requests.post', mock.Mock()), \
             mock.patch('json.dumps', mock.Mock()):
            notification_pusher.notification_worker(task_mock, task_queue_mock)

        task_queue_mock.put.assert_called_once_with((task_mock, 'ack'))

    def test_notification_worker_with_request_exception(self):
        task_mock = mock.MagicMock()
        task_queue_mock = mock.Mock()

        logger_mock = mock.Mock()
        notification_pusher.logger = logger_mock

        with mock.patch('requests.post', mock.Mock(side_effect=RequestException('Test exception'))), \
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

    def test_done_with_processed_tasks(self):
        task_mock = mock.Mock()
        task_queue_mock = mock.Mock()
        task_queue_mock.qsize.return_value = 1
        task_queue_mock.get_nowait.side_effect = lambda: (task_mock, 'fake_action_name')

        logger_mock = mock.Mock()
        notification_pusher.logger = logger_mock

        notification_pusher.done_with_processed_tasks(task_queue_mock)
        self.assertEqual(logger_mock.debug.call_count, 2)

    def test_install_signal_handlers(self):
        gevent_mock = mock.Mock()
        with mock.patch('gevent.signal', gevent_mock):
            notification_pusher.install_signal_handlers()

        stop_handler = notification_pusher.stop_handler
        gevent_mock.assert_any_call(signal.SIGTERM, stop_handler, signal.SIGTERM)
        gevent_mock.assert_any_call(signal.SIGINT, stop_handler, signal.SIGINT)
        gevent_mock.assert_any_call(signal.SIGHUP, stop_handler, signal.SIGHUP)
        gevent_mock.assert_any_call(signal.SIGQUIT, stop_handler, signal.SIGQUIT)

    def test_parse_cmd_args_correct_all_params(self):
        args = ['--config', './config',
                '--pid', './pidfile',
                '--daemon']
        parser = notification_pusher.parse_cmd_args(args)
        self.assertEqual(parser.config, './config',)
        self.assertEqual(parser.pidfile, './pidfile',)
        self.assertTrue(parser.daemon)

    def test_parse_cmd_args_with_config(self):
        args = ['--config', './config']
        parser = notification_pusher.parse_cmd_args(args)
        self.assertEqual(parser.config, './config',)
        self.assertIsNone(parser.pidfile)
        self.assertFalse(parser.daemon)

    def test_parse_cmd_args_without_config(self):
        sys_exit_mock = mock.Mock()
        with mock.patch('sys.exit', sys_exit_mock):
            notification_pusher.parse_cmd_args([])
        sys_exit_mock.assert_called_once_with(2)

    def test_stop_handler(self):
        logger_mock = mock.Mock()
        signum = 100
        offset = 128
        notification_pusher.logger = logger_mock
        notification_pusher.stop_handler(signum)
        exit_code = notification_pusher.exit_code
        run_application = notification_pusher.run_application
        self.assertFalse(run_application)
        self.assertEqual(exit_code, signum + offset)


    def test_main_check_args_is_daemon_and_pidfile(self):
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
             patch('source.notification_pusher.sleep', mock_stop_cycle):
            return_exitcode = notification_pusher.main(args)
            self.assertEqual(return_exitcode, exit_code)
            self.assertRaises(Exception)
            notification_pusher.run_application = True