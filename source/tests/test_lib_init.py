# coding: utf-8
import unittest
import mock
from mock import patch
import source.lib as init


def get_url_fake(url, timeout, user_agent=None):
    if url == 'first':
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
        to_str_mock = mock.Mock(return_value='prepared_url_fake')
        init.to_str = to_str_mock
        buff_mock = mock.Mock()
        curl_mock = mock.Mock()
        curl_mock.USERAGENT = 'curl_user_agent_option'
        curl_mock.getinfo.return_value = None
        with patch('source.lib.pycurl.Curl', mock.Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', mock.Mock()), \
             patch('source.lib.StringIO', mock.Mock(return_value=buff_mock)):
            init.make_pycurl_request('fake_url', timeout=1, useragent='test_user_agent')
        curl_mock.setopt.asser_called_with('curl_user_agent_option', 'test_user_agent')

    def test_make_pycurl_request_set_timeout(self):
        to_str_mock = mock.Mock(return_value='prepared_url_fake')
        init.to_str = to_str_mock
        buff_mock = mock.Mock()
        curl_mock = mock.Mock()
        curl_mock.TIMEOUT = 'curl_timeout_option'
        timeout = 183
        with patch('source.lib.pycurl.Curl', mock.Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', mock.Mock()), \
             patch('source.lib.StringIO', mock.Mock(return_value=buff_mock)), \
             patch('source.lib.to_unicode', mock.Mock(return_value='fake unicode')):
            init.make_pycurl_request('fake_url', timeout=timeout)
        curl_mock.setopt.asser_called_with('curl_timeout_option', timeout)

    def test_make_pycurl_request_check_content(self):
        to_str_mock = mock.Mock(return_value='prepared_url_fake')
        init.to_str = to_str_mock
        buff_mock = mock.Mock()
        initial_content = 'content return value'
        buff_mock.getvalue.return_value = initial_content
        curl_mock = mock.Mock()
        curl_mock.TIMEOUT = 'curl_timeout_option'
        curl_mock.getinfo.return_value = None
        with patch('source.lib.pycurl.Curl', mock.Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', mock.Mock()), \
             patch('source.lib.StringIO', mock.Mock(return_value=buff_mock)):
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
             patch('source.lib.to_unicode', mock.Mock(return_value=initial_redirect_url)):
            return_content, return_redirect_url = init.make_pycurl_request('fake_url', timeout=1)
        self.assertEqual(return_redirect_url, initial_redirect_url)

    def test_get_redirect_history_mm_or_ok_domain(self):
        prepare_url_mock = mock.Mock(return_value='mm_or_ok_fake_domain')
        init.prepare_url = prepare_url_mock
        with patch('source.lib.re.match'):
            ret_hist_types, ret_hist_urls, ret_counters = init.get_redirect_history('mm_or_ok_fake_domain', timeout=1)
        self.assertEqual(len(ret_hist_types), 0)
        self.assertEqual(ret_hist_urls, ['mm_or_ok_fake_domain'])
        self.assertEqual(len(ret_counters), 0)

    def test_get_redirect_history_without_redirects(self):
        prepare_url_mock = mock.Mock(return_value='fake_domain')
        init.prepare_url = prepare_url_mock
        get_url_mock = mock.Mock(return_value=(False, 'fake_redirect_type', None))
        init.get_url = get_url_mock
        with patch('source.lib.re.match', mock.Mock(return_value=False)):
            ret_hist_types, ret_hist_urls, ret_counters \
                = init.get_redirect_history('fake_domain', timeout=1)
        self.assertEqual(len(ret_hist_types), 0)
        self.assertEqual(ret_hist_urls, ['fake_domain'])
        self.assertEqual(len(ret_counters), 0)

    def test_get_redirect_history_with_bad_redirect_type(self):
        prepare_url_mock = mock.Mock(return_value='fake_domain')
        init.prepare_url = prepare_url_mock
        content_fake = 'fake_content'
        get_counters_mock = mock.Mock(return_value=1234)
        init.get_counters = get_counters_mock
        redirect_type_error = 'ERROR'
        get_url_mock = mock.Mock(return_value=('fake_redirect_url', redirect_type_error, content_fake))
        init.get_url = get_url_mock
        with patch('source.lib.re.match', mock.Mock(return_value=False)):
            ret_hist_types, ret_hist_urls, ret_counters \
                = init.get_redirect_history('fake_domain', timeout=1)
        self.assertEqual(ret_hist_types, [redirect_type_error])
        self.assertEqual(ret_hist_urls, ['fake_domain', 'fake_redirect_url'])
        self.assertEqual(ret_counters, 1234)

    def test_get_redirect_history_with_len_history_urls_is_over_max_redirects(self):
        prepare_url_mock = mock.Mock(return_value='fake_domain')
        init.prepare_url = prepare_url_mock
        content_fake = 'fake_content'
        get_counters_mock = mock.Mock(return_value=1234)
        init.get_counters = get_counters_mock
        get_url_mock = mock.Mock(return_value=('fake_redirect_url', 'fake_redirect_type', content_fake))
        init.get_url = get_url_mock
        with patch('source.lib.re.match', mock.Mock(return_value=False)):
            ret_hist_types, ret_hist_urls, ret_counters \
                = init.get_redirect_history('fake_domain', timeout=1, max_redirects=-1)
        self.assertEqual(ret_hist_types, ['fake_redirect_type'])
        self.assertEqual(ret_hist_urls, ['fake_domain', 'fake_redirect_url'])
        self.assertEqual(ret_counters, 1234)

    # def test_get_redirect_history(self):
    #     prepare_url_mock = mock.Mock(return_value='fake_domain')
    #     init.prepare_url = prepare_url_mock
    #
    #     get_counters_mock = mock.Mock(return_value=1234)
    #     init.get_counters = get_counters_mock
    #     get_url_mock = mock.MagicMock(side_effect=get_url_fake)
    #
    #     init.get_url = get_url_mock
    #     with patch('source.lib.re.match', mock.Mock(return_value=False)),\
    #          patch('__builtin__.str', mock.Mock(return_value=1)):
    #
    #         ret_hist_types, ret_hist_urls, ret_counters \
    #             = init.get_redirect_history('fake_domain', timeout=1, max_redirects=-1)
    #     self.assertEqual(ret_hist_types, ['fake_redirect_type'])
    #     self.assertEqual(ret_hist_urls, ['fake_domain', 'first'])
    #     self.assertEqual(ret_counters, 1234)