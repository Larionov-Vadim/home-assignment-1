# coding: utf-8
import json
import unittest
import mock
import signal
import tarantool
from mock import patch, Mock
from source import notification_pusher
from requests import RequestException
from gevent import queue as gevent_queue
from source.lib.utils import Config
from tarantool_queue import tarantool_queue


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


class StubTarantoolQueueTask(object):
    def __init__(self):
        self.stub_data = dict()
        self.url = 'https://fake.callback.url'  # callback url
        self.stub_data['callback_url'] = self.url

    @property
    def task_id(self):
        return -1   # fake id

    @property
    def data(self):
        return self

    def copy(self):
        return self.stub_data


class NotificationPusherTestCase(unittest.TestCase):
    def test_notification_worker_positive_test(self):
        task = StubTarantoolQueueTask()
        task_queue_mock = Mock()
        request_post_mock = Mock()
        kwargs = {'fake_key': 'fake_value'}
        with patch('source.notification_pusher.logger', Mock()), \
             patch('requests.post', request_post_mock):
            notification_pusher.notification_worker(task, task_queue_mock, **kwargs)
        request_post_mock.assert_called_once_with(
            task.url,
            data=json.dumps(task.data.copy()),
            **kwargs
        )
        task_queue_mock.put.assert_called_once_with((task, 'ack'))

    def test_notification_worker_with_request_exception(self):
        task = StubTarantoolQueueTask()
        task_queue_mock = Mock()
        with patch('requests.post', mock.Mock(side_effect=RequestException('Test exception'))), \
             patch('source.notification_pusher.logger', Mock()):
            notification_pusher.notification_worker(task, task_queue_mock)
        task_queue_mock.put.assert_called_once_with((task, 'bury'))


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
        task_mock.fake_action.side_effect = tarantool.DatabaseError('Test exception')
        task_queue_mock = Mock()
        task_queue_mock.qsize.return_value = 1
        task_queue_mock.get_nowait.side_effect = lambda: (task_mock, 'fake_action')
        logger_mock = Mock()
        with patch('source.notification_pusher.logger', logger_mock):
            notification_pusher.done_with_processed_tasks(task_queue_mock)
        self.assertEqual(logger_mock.exception.call_count, 1)


    def test_install_signal_handlers(self):
        gevent_mock = Mock()
        with patch('gevent.signal', gevent_mock):
            notification_pusher.install_signal_handlers()
        stop_handler = notification_pusher.stop_handler
        gevent_mock.assert_any_call(signal.SIGTERM, stop_handler, signal.SIGTERM)
        gevent_mock.assert_any_call(signal.SIGINT, stop_handler, signal.SIGINT)
        gevent_mock.assert_any_call(signal.SIGHUP, stop_handler, signal.SIGHUP)
        gevent_mock.assert_any_call(signal.SIGQUIT, stop_handler, signal.SIGQUIT)


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
        with patch('source.lib.utils.parse_cmd_args', mock_parse_cmd_args),\
             patch('source.lib.utils.daemonize', mock_daemonize),\
             patch('source.lib.utils.create_pidfile', mock_create_pidfile),\
             patch('source.lib.utils.load_config_from_pyfile', mock_load_config_from_pyfile),\
             patch('source.notification_pusher.main_preparation', mock.Mock()),\
             patch('source.notification_pusher.main_run', mock.Mock()),\
             patch('source.notification_pusher.os.path.realpath', mock.Mock()),\
             patch('source.notification_pusher.os.path.expanduser', mock.Mock()):
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
        with patch('source.lib.utils.parse_cmd_args', mock_parse_cmd_args),\
             patch('source.lib.utils.daemonize', mock_daemonize),\
             patch('source.lib.utils.create_pidfile', mock_create_pidfile),\
             patch('source.lib.utils.load_config_from_pyfile', mock_load_config_from_pyfile),\
             patch('source.notification_pusher.main_preparation', mock.Mock()),\
             patch('source.notification_pusher.main_run', mock.Mock()),\
             patch('source.notification_pusher.os.path.realpath', mock.Mock()),\
             patch('source.notification_pusher.os.path.expanduser', mock.Mock()):
            return_exitcode = notification_pusher.main(args)
            self.assertEqual(return_exitcode, exit_code)
            self.assertEqual(mock_daemonize.call_count, 0)
            self.assertEqual(mock_create_pidfile.call_count, 0)
            notification_pusher.run_application = True

    def test_main_run_bad_parametr(self):
        uncorrect_config = 'everything bad'
        mock_stop_cycle = mock.Mock(side_effect=stop_cycle)
        with patch('source.notification_pusher.main_loop', mock.Mock(side_effect=[True])),\
             patch('source.notification_pusher.sleep', mock_stop_cycle),\
             patch('source.notification_pusher.logger', mock.Mock()):
            with self.assertRaises(AttributeError):
                notification_pusher.main_run(uncorrect_config)

    def test_main_run_bad(self):
        notification_pusher.run_application = False
        mock_logger = mock.Mock()
        with patch('source.notification_pusher.logger', mock_logger):
            notification_pusher.main_run(config)
            notification_pusher.run_application = True
           # self.assertGreater(mock_logger.info.call_count, 0)



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

    def test_main_main_preparation_ok(self):
       with patch('source.notification_pusher.dictConfig', mock.Mock()):
           notification_pusher.main_preparation(config)

    def test_main_main_preparation_bad(self):
       uncorrect_config = 'smth bad'
       with patch('source.notification_pusher.dictConfig', mock.Mock()):
           with self.assertRaises(AttributeError):
               notification_pusher.main_preparation(uncorrect_config)