# coding: utf-8
import unittest
import mock
from mock import patch, Mock
import source.lib as init


def get_url_fake(url, timeout, user_agent):
    if url == 'fake_domain':
        return 'stop_loop', 'fake_redirect_type', 'fake_content_1'
    if url == 'stop_loop':
        return None, 'fake_redirect_type_2', 'fake_content_2'


class InitTestCase(unittest.TestCase):
    def test_fix_market_url_correct_test(self):
        url = 'market://correct_test'
        return_str = init.fix_market_url(url)
        self.assertEqual(return_str, 'http://play.google.com/store/apps/correct_test')

    # Что за магия? Почему assertEquals не работает?
    def test_fix_market_url_magic_test(self):
        url = 'market://testing'
        return_str = init.fix_market_url(url)
        self.assertNotEqual(return_str, 'http://play.google.com/store/apps/testing')

    def test_fix_market_with_empty_url(self):
        url = ''
        return_str = init.fix_market_url(url)
        self.assertEqual(return_str, 'http://play.google.com/store/apps/')

    def test_fix_market_without_market_in_url(self):
        url = 'fuuu'
        return_str = init.fix_market_url(url)
        self.assertEqual(return_str, 'http://play.google.com/store/apps/fuuu')


    def test_make_pycurl_request_set_user_agent(self):
        buff_mock = mock.Mock()
        curl_mock = mock.Mock()
        curl_mock.USERAGENT = 'curl_user_agent_option'
        curl_mock.getinfo.return_value = None
        with patch('source.lib.pycurl.Curl', Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', Mock()), \
             patch('source.lib.StringIO', Mock(return_value=buff_mock)), \
             patch('source.lib.to_str', Mock(return_value='prepared_url_fake')):
            init.make_pycurl_request('fake_url', timeout=1, useragent='test_user_agent')
        curl_mock.setopt.asser_called_with('curl_user_agent_option', 'test_user_agent')

    def test_make_pycurl_request_set_timeout(self):
        buff_mock = mock.Mock()
        curl_mock = mock.Mock()
        curl_mock.TIMEOUT = 'curl_timeout_option'
        timeout = 183
        with patch('source.lib.pycurl.Curl', mock.Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', mock.Mock()), \
             patch('source.lib.StringIO', mock.Mock(return_value=buff_mock)), \
             patch('source.lib.to_unicode', mock.Mock(return_value='fake unicode')), \
             patch('source.lib.to_str', Mock(return_value='prepared_url_fake')):
            init.make_pycurl_request('fake_url', timeout=timeout)
        curl_mock.setopt.asser_called_with('curl_timeout_option', timeout)

    def test_make_pycurl_request_check_content(self):
        buff_mock = mock.Mock()
        initial_content = 'content return value'
        buff_mock.getvalue.return_value = initial_content
        curl_mock = mock.Mock()
        curl_mock.TIMEOUT = 'curl_timeout_option'
        curl_mock.getinfo.return_value = None
        with patch('source.lib.pycurl.Curl', mock.Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', mock.Mock()), \
             patch('source.lib.StringIO', mock.Mock(return_value=buff_mock)), \
             patch('source.lib.to_str', Mock(return_value='prepared_url_fake')):
            return_content, return_redirect_url = init.make_pycurl_request('fake_url', timeout=1)
        self.assertEqual(return_content, initial_content)

    def test_make_pycurl_request_check_redirect_url(self):
        to_str_mock = mock.Mock(return_value='prepared_url_fake')
        init.to_str = to_str_mock
        buff_mock = mock.Mock()
        curl_mock = mock.Mock()
        initial_redirect_url = 'test_redirect_url'
        with patch('source.lib.pycurl.Curl', mock.Mock(return_value=curl_mock)), \
             patch('source.lib.StringIO', mock.Mock(return_value=buff_mock)), \
             patch('source.lib.prepare_url', mock.Mock()), \
             patch('source.lib.to_unicode', mock.Mock(return_value=initial_redirect_url)), \
             patch('source.lib.to_str', Mock(return_value='prepared_url_fake')):
            ignore, return_redirect_url = init.make_pycurl_request('fake_url', timeout=1)
        self.assertEqual(return_redirect_url, initial_redirect_url)


    def test_get_redirect_history_mm_or_ok_domain(self):
        with patch('source.lib.re.match', mock.Mock()), \
             patch('source.lib.prepare_url', Mock(return_value='mm_or_ok_fake_domain')):
            ret_hist_types, ret_hist_urls, ret_counters = init.get_redirect_history('mm_or_ok_fake_domain', timeout=1)
        self.assertEqual(len(ret_hist_types), 0)
        self.assertEqual(ret_hist_urls, ['mm_or_ok_fake_domain'])
        self.assertEqual(len(ret_counters), 0)

    def test_get_redirect_history_without_redirects(self):
        get_url_mock = Mock(return_value=(False, 'fake_redirect_type', None))
        with patch('source.lib.re.match', mock.Mock(return_value=False)), \
             patch('source.lib.prepare_url', return_value='fake_domain'), \
             patch('source.lib.get_url', get_url_mock):
            ret_hist_types, ret_hist_urls, ret_counters \
                = init.get_redirect_history('fake_domain', timeout=1)
        self.assertEqual(len(ret_hist_types), 0)
        self.assertEqual(ret_hist_urls, ['fake_domain'])
        self.assertEqual(len(ret_counters), 0)

    def test_get_redirect_history_with_bad_redirect_type(self):
        content_fake = 'fake_content'
        get_counters_mock = Mock(return_value=1234)
        redirect_type_error = 'ERROR'
        get_url_mock = mock.Mock(return_value=('fake_redirect_url', redirect_type_error, content_fake))
        with patch('source.lib.re.match', mock.Mock(return_value=False)), \
             patch('source.lib.prepare_url', Mock(return_value='fake_domain')), \
             patch('source.lib.get_counters', get_counters_mock), \
             patch('source.lib.get_url', get_url_mock):
            ret_hist_types, ret_hist_urls, ret_counters \
                = init.get_redirect_history('fake_domain', timeout=1)
        self.assertEqual(ret_hist_types, [redirect_type_error])
        self.assertEqual(ret_hist_urls, ['fake_domain', 'fake_redirect_url'])
        self.assertEqual(ret_counters, 1234)

    def test_get_redirect_history_with_len_history_urls_is_over_max_redirects(self):
        content_fake = 'fake_content'
        get_counters_mock = mock.Mock(return_value=1234)
        get_url_mock = mock.Mock(return_value=('fake_redirect_url', 'fake_redirect_type', content_fake))
        with patch('source.lib.re.match', mock.Mock(return_value=False)), \
             patch('source.lib.prepare_url', Mock(return_value='fake_domain')), \
             patch('source.lib.get_counters', get_counters_mock), \
             patch('source.lib.get_url', get_url_mock):
            ret_hist_types, ret_hist_urls, ret_counters \
                = init.get_redirect_history('fake_domain', timeout=1, max_redirects=-1)
        self.assertEqual(ret_hist_types, ['fake_redirect_type'])
        self.assertEqual(ret_hist_urls, ['fake_domain', 'fake_redirect_url'])
        self.assertEqual(ret_counters, 1234)

    def test_get_redirect_history_with_two_iteration(self):
        get_url_mock = mock.Mock(side_effect=get_url_fake)
        with patch('source.lib.re.match', mock.Mock(return_value=False)),\
             patch('__builtin__.str', mock.Mock(return_value=1)), \
             patch('source.lib.prepare_url', Mock(return_value='fake_domain')), \
             patch('source.lib.get_counters', Mock(return_value=1234)), \
             patch('source.lib.get_url', get_url_mock):
            ret_hist_types, ret_hist_urls, ret_counters \
                = init.get_redirect_history('fake_domain', timeout=1)
        self.assertEqual(ret_hist_types, ['fake_redirect_type'])
        self.assertEqual(ret_hist_urls, ['fake_domain', 'stop_loop'])
        self.assertEqual(ret_counters, 1234)


    def test_get_counters_empty_content(self):
        content = ''
        waiting_result_counters = []
        result = init.get_counters(content)
        self.assertEqual(waiting_result_counters, result)

    def test_get_counters_not_empty_content(self):
        content = '<html><body>' \
                  '<script async="" src="https://ssl.google-analytics.com/ga.js"></script>' \
                  '</body></html>'
        waiting_result_counters = ['GOOGLE_ANALYTICS']
        result = init.get_counters(content)
        self.assertEqual(waiting_result_counters, result)


    def test_check_for_meta_with_empty_content_and_no_http_equiv(self):
        content = ''
        url = 'url'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_content_ok_and_no_http_equiv(self):
        url = 'url'
        content = '<html><body>' \
                  '<meta content="one;two">' \
                  '</body></html>'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_content_ok_and_http_equiv_bad(self):
        url = 'url'
        content = '<html><body>' \
                  '<meta content="one;two" http-equiv="no refresh">' \
                  '</body></html>'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_content_bad_and_http_equiv_ok(self):
        url = 'url'
        content = '<html><body>' \
                  '<meta content="one" http-equiv="refresh">' \
                  '</body></html>'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_content_ok_and_http_equiv_ok(self):
        url = 'url'
        content = '<html><body>' \
                  '<meta content="one;two" http-equiv="refresh">' \
                  '</body></html>'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)


    def test_get_url_without_redirects(self):
        prepare_url_mock = Mock()
        with patch('source.lib.make_pycurl_request', Mock(return_value=('fake_content', None))), \
             patch('source.lib.prepare_url', prepare_url_mock), \
             patch('source.lib.prepare_url.check_for_meta', Mock(return_value=None)):
            ignore, ret_type, ret_content = init.get_url('fake_url', timeout=1)
        prepare_url_mock.assert_called_once_with(None)
        self.assertIsNone(ret_type)
        self.assertEqual(ret_content, 'fake_content')


    def test_prepare_url_with_none_url(self):
        url = None
        waiting_result = None
        result = init.prepare_url(url)
        self.assertEqual(waiting_result, result)

    def test_prepare_url_url_is_ok(self):
        url = 'https://github.com/'
        mock_urlunparse = mock.Mock()
        with patch('source.lib.urlunparse', mock_urlunparse):
            result = init.prepare_url(url)
        self.assertIsNot(mock_urlunparse.called, 0)

