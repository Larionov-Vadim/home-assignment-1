import unittest
import mock
from source import notification_pusher


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
        pid = 139
        with mock.patch('os.fork', mock.Mock(return_value=pid)), \
             mock.patch('os._exit', os_exit_mock, create=True):
            notification_pusher.daemonize()
        assert os_exit_mock.called

    def test_daemonize_pid_zero_then_not_zero(self):
        pid = [0, 724]                          # pid == 0 and pid != 0
        os_exit_mock = mock.Mock()
        os_fork_mock = mock.Mock()
        os_fork_mock.side_effect = pid

        with mock.patch('os.fork', os_fork_mock, create=True), \
             mock.patch('os._exit', os_exit_mock, create=True), \
             mock.patch('os.setsid', mock.Mock()):
            notification_pusher.daemonize()
        assert os_exit_mock.called

    def test_daemonize_pid_alvays_zero(self):
        os_exit_mock = mock.Mock()
        os_fork_mock = mock.Mock(return_value=0)  # pid is always zero

        with mock.patch('os.fork', os_fork_mock, create=True), \
             mock.patch('os._exit', os_exit_mock, create=True), \
             mock.patch('os.setsid', mock.Mock()):
            notification_pusher.daemonize()
        assert not os_exit_mock.called

    def test_daemonize_raise_os_error_exception(self):
        os_fork_mock = mock.Mock(side_effect=OSError(0, 'Boom!'))
        with mock.patch('os.fork', os_fork_mock, create=True):
            self.assertRaises(Exception, notification_pusher.daemonize)

    def test_daemonize_pid_zero_then_raise_os_error_exception(self):
        os_fork_mock = mock.Mock(side_effect=[0, OSError(0, 'Boom!')])
        with mock.patch('os.fork', os_fork_mock, create=True), \
             mock.patch('os.setsid', mock.Mock(), create=True):
            self.assertRaises(Exception, notification_pusher.daemonize)
