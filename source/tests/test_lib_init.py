# coding: utf-8
import unittest
import mock
from mock import patch, Mock
import source.lib as init
import pycurl
from urlparse import urlparse


def get_url_fake(url, timeout, user_agent):
    if url == 'fake_domain':
        return 'stop_loop', 'fake_redirect_type', 'fake_content_1'
    if url == 'stop_loop':
        return None, 'fake_redirect_type_2', 'fake_content_2'


class InitTestCase(unittest.TestCase):
    def test_fix_market_url_correct_test(self):
        url = 'market://correct_test'
        actual_url = init.fix_market_url(url)
        self.assertEqual(actual_url, 'http://play.google.com/store/apps/correct_test')

    def test_fix_market_url_when_url_is_empty(self):
        url = ''
        actual_url = init.fix_market_url(url)
        self.assertEqual(actual_url, 'http://play.google.com/store/apps/')

    def test_fix_market_url_when_url_is_None(self):
        url = None
        self.assertRaises(AttributeError, init.fix_market_url, url)

    def test_fix_market_url_when_url_is_number(self):
        url = 54321
        self.assertRaises(AttributeError, init.fix_market_url, url)


    def test_make_pycurl_request_set_user_agent(self):
        buff_mock = Mock()
        curl_mock = Mock()
        curl_mock.USERAGENT = 'curl_user_agent_option'
        curl_mock.getinfo.return_value = None
        with patch('source.lib.pycurl.Curl', Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', Mock()), \
             patch('source.lib.StringIO', Mock(return_value=buff_mock)), \
             patch('source.lib.to_str', Mock(return_value='prepared_url_fake')):
            init.make_pycurl_request('fake_url', timeout=1, useragent='test_user_agent')
        expected_call = mock.call('curl_user_agent_option', 'test_user_agent')
        curl_mock.setopt.assert_has_calls(expected_call)

    def test_make_pycurl_request_set_timeout(self):
        buff_mock = Mock()
        curl_mock = Mock()
        curl_mock.TIMEOUT = 'curl_timeout_option'
        timeout = 183
        with patch('source.lib.pycurl.Curl', Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', Mock()), \
             patch('source.lib.StringIO', Mock(return_value=buff_mock)), \
             patch('source.lib.to_unicode', Mock(return_value='fake unicode')), \
             patch('source.lib.to_str', Mock(return_value='prepared_url_fake')):
            init.make_pycurl_request('fake_url', timeout=timeout)
        curl_mock.setopt.asser_called_with('curl_timeout_option', timeout)

    def test_make_pycurl_request_check_content(self):
        buff_mock = Mock()
        expected_content = 'content return value'
        buff_mock.getvalue.return_value = expected_content
        curl_mock = Mock()
        curl_mock.TIMEOUT = 'curl_timeout_option'
        curl_mock.getinfo.return_value = None
        with patch('source.lib.pycurl.Curl', mock.Mock(return_value=curl_mock)), \
             patch('source.lib.prepare_url', mock.Mock()), \
             patch('source.lib.StringIO', mock.Mock(return_value=buff_mock)), \
             patch('source.lib.to_str', Mock(return_value='prepared_url_fake')):
            actual_content, ignore = init.make_pycurl_request('fake_url', timeout=1)
        self.assertEqual(actual_content, expected_content)

    def test_make_pycurl_request_check_redirect_url(self):
        buff_mock = Mock()
        curl_mock = Mock()
        curl_mock.getinfo.return_value = 'redirect_url'
        expected_redirect_url = 'unicode_redirect_url'
        with patch('source.lib.pycurl.Curl', mock.Mock(return_value=curl_mock)), \
             patch('source.lib.StringIO', mock.Mock(return_value=buff_mock)), \
             patch('source.lib.prepare_url', mock.Mock()), \
             patch('source.lib.to_unicode', mock.Mock(return_value=expected_redirect_url)), \
             patch('source.lib.to_str', Mock(return_value='prepared_url_fake')):
            ignore, actual_redirect_url = init.make_pycurl_request('fake_url', timeout=1)
        self.assertEqual(actual_redirect_url, expected_redirect_url)

    def test_get_redirect_history_mm_domain(self):
        url_fake = 'https://my.mail.ru/apps/test'
        with patch('source.lib.prepare_url', Mock(return_value=url_fake)):
            actual_history_types, actual_history_urls, actual_counters \
                = init.get_redirect_history(url_fake, timeout=1)
        self.assertEqual(actual_history_types, [])
        self.assertEqual(actual_history_urls, [url_fake])
        self.assertEqual(actual_counters, [])

    def test_get_redirect_history_ok_domain(self):
        url_fake = 'https://www.odnoklassniki.ru/test'
        with patch('source.lib.prepare_url', Mock(return_value=url_fake)):
            actual_history_types, actual_history_urls, actual_counters \
                = init.get_redirect_history(url_fake, timeout=1)
        self.assertEqual(actual_history_types, [])
        self.assertEqual(actual_history_urls, [url_fake])
        self.assertEqual(actual_counters, [])

    def test_get_redirect_history_without_redirects(self):
        url_fake = 'http://fake.url.com'
        get_url_mock = Mock(return_value=(False, url_fake, None))
        with patch('source.lib.prepare_url', return_value=url_fake), \
             patch('source.lib.get_url', get_url_mock):
            actual_history_types, actual_history_urls, actual_counters \
                = init.get_redirect_history('fake_domain', timeout=1)
        self.assertEqual(actual_history_types, [])
        self.assertEqual(actual_history_urls, [url_fake])
        self.assertEqual(actual_counters, [])

    def test_get_redirect_history_with_bad_redirect_type(self):
        content_fake = 'fake_content'
        url_fake = 'http://fake.url.com'
        url_redirect_fake = 'http://redirect.fake.url.com'
        get_counters_mock = Mock(return_value=['YA_METRICA'])
        redirect_type_error = 'ERROR'
        get_url_mock = Mock(return_value=(url_redirect_fake, redirect_type_error, content_fake))
        with patch('source.lib.prepare_url', Mock(return_value=url_fake)), \
             patch('source.lib.get_counters', get_counters_mock), \
             patch('source.lib.get_url', get_url_mock):
            actual_hist_types, actual_hist_urls, actual_counters \
                = init.get_redirect_history('fake_domain', timeout=1)
        self.assertEqual(actual_hist_types, [redirect_type_error])
        self.assertEqual(actual_hist_urls, [url_fake, url_redirect_fake])
        self.assertEqual(actual_counters, ['YA_METRICA'])

    def test_get_redirect_history_with_len_history_urls_is_over_max_redirects(self):
        content_fake = 'fake_content'
        url_fake = 'http://fake.url.com'
        url_redirect_fake = 'http://redirect.fake.url.com'
        get_counters_mock = Mock(return_value=['TEST_METRIC'])
        get_url_mock = Mock(return_value=(url_redirect_fake, 'fake_redirect_type', content_fake))
        with patch('source.lib.prepare_url', Mock(return_value=url_fake)), \
             patch('source.lib.get_counters', get_counters_mock), \
             patch('source.lib.get_url', get_url_mock):
            actual_hist_types, actual_hist_urls, actual_counters \
                = init.get_redirect_history('fake_domain', timeout=1, max_redirects=-1)
        self.assertEqual(actual_hist_types, ['fake_redirect_type'])
        self.assertEqual(actual_hist_urls, [url_fake, url_redirect_fake])
        self.assertEqual(actual_counters, ['TEST_METRIC'])

    def test_get_redirect_history_with_two_iteration(self):
        get_url_mock = Mock(side_effect=get_url_fake)
        with patch('source.lib.prepare_url', Mock(return_value='fake_domain')), \
             patch('source.lib.get_counters', Mock(return_value=['FAKE_METRICS'])), \
             patch('source.lib.get_url', get_url_mock):
            actual_hist_types, actual_hist_urls, actual_counters \
                = init.get_redirect_history('fake_domain', timeout=1)
        self.assertEqual(actual_hist_types, ['fake_redirect_type'])
        self.assertEqual(actual_hist_urls, ['fake_domain', 'stop_loop'])
        self.assertEqual(actual_counters, ['FAKE_METRICS'])


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
        url = 'https://github.com/'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_content_ok_and_no_http_equiv(self):
        url = 'https://github.com/'
        content = '<html><body>' \
                  '<meta content="one;two">' \
                  '</body></html>'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_content_ok_and_http_equiv_bad(self):
        url = 'https://github.com/'
        content = '<html><body>' \
                  '<meta content="one;two" http-equiv="no refresh">' \
                  '</body></html>'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_content_bad_and_http_equiv_ok(self):
        url = 'https://github.com/'
        content = '<html><body>' \
                  '<meta content="one" http-equiv="refresh">' \
                  '</body></html>'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_content_ok_and_http_equiv_ok(self):
        url = 'https://github.com/'
        content = '<html><body>' \
                  '<meta content="one;two" http-equiv="refresh">' \
                  '</body></html>'
        waiting_result_counters = None
        result = init.check_for_meta(content, url)
        self.assertEqual(waiting_result_counters, result)

    def test_check_for_meta_with_m(self):
        url = 'https://github.com/'
        content = '<html><body>' \
                  '<meta content="one;url=two.html" http-equiv="refresh">'\
                  '</body></html>'
        waiting_result = 'https://github.com/two.html'
        result = init.check_for_meta(content, url)
        self.assertEqual(result, waiting_result)


    def test_get_url_without_redirects(self):
        expected_content = 'fake content'
        prepare_url_mock = Mock()
        pycurl_mock = Mock(return_value=(expected_content, None))
        with patch('source.lib.make_pycurl_request', pycurl_mock), \
             patch('source.lib.prepare_url', prepare_url_mock), \
             patch('source.lib.prepare_url.check_for_meta', Mock(return_value=None)):
            ignore, actual_type, actual_content = init.get_url('fake_url', timeout=1)
        prepare_url_mock.assert_called_once_with(None)
        self.assertIsNone(actual_type)
        self.assertEqual(actual_content, expected_content)

    def test_get_url_with_pycurl_error(self):
        expected_url = 'https://fake.url.com'
        with patch('source.lib.make_pycurl_request', Mock(side_effect=pycurl.error)), \
             patch('source.lib.logger', Mock()):
            actual_url, actual_type, actual_content = \
                init.get_url(expected_url, timeout=1, user_agent='fake_user')
        self.assertEqual(actual_url, expected_url)
        self.assertEqual(actual_type, 'ERROR')
        self.assertIsNone(actual_content)

    def test_get_url_with_value_error(self):
        expected_url = 'https://fake.url.com'
        with patch('source.lib.make_pycurl_request', Mock(side_effect=ValueError)), \
             patch('source.lib.logger', Mock()):
            actual_url, actual_type, actual_content = init.get_url(expected_url, timeout='value')
        self.assertEqual(actual_url, expected_url)
        self.assertEqual(actual_type, 'ERROR')
        self.assertIsNone(actual_content)

    def test_get_url_with_ok_redirect(self):
        url = 'http://fake.url.com'
        expected_content = 'Bingo!'
        redirect_url = 'http://www.odnoklassniki.ru/lalala.st.redirect'
        pycurl_mock = Mock(return_value=(expected_content, redirect_url))
        with patch('source.lib.make_pycurl_request', pycurl_mock):
            actual_url, actual_type, actual_content = \
                init.get_url(url, timeout=10, user_agent='fake_user')
        self.assertIsNone(actual_url)
        self.assertIsNone(actual_type)
        self.assertEqual(actual_content, expected_content)

    def test_get_url_with_new_redirect_url(self):
        url = 'http://fake.url.com'
        expected_type = init.REDIRECT_HTTP
        expected_content = 'fake content'
        redirect_url = 'https://redirect.fake.url.org'
        prepare_url = 'http://prepare.redirect.url.com'
        pycurl_mock = Mock(return_value=(expected_content, redirect_url))
        prepare_url_mock = Mock(return_value=prepare_url)
        with patch('source.lib.make_pycurl_request', pycurl_mock),\
             patch('source.lib.logger', Mock()), \
             patch('source.lib.prepare_url', prepare_url_mock):
            actual_url, actual_type, actual_content = \
                init.get_url(url, timeout=3, user_agent='fake_user')
        prepare_url_mock.assert_called_once_with(redirect_url)
        self.assertEqual(actual_url, prepare_url)
        self.assertEqual(actual_type, expected_type)
        self.assertEqual(actual_content, expected_content)

    def test_get_url_with_redirect_in_meta_tag(self):
        url = 'http://fake.url.com'
        expected_type = init.REDIRECT_META
        expected_content = 'fake content'
        prepare_url = 'http://prepare.meta.redirect.url.com'
        pycurl_mock = Mock(return_value=(expected_content, None))
        prepare_url_mock = Mock(return_value=prepare_url)
        with patch('source.lib.make_pycurl_request', pycurl_mock),\
             patch('source.lib.logger', Mock()), \
             patch('source.lib.prepare_url', prepare_url_mock),\
             patch('source.lib.check_for_meta', Mock(return_value='http://meta.redirect.url')):
            actual_url, actual_type, actual_content = \
                init.get_url(url, timeout=10, user_agent='fake_user')
        prepare_url_mock.assert_called_once_with('http://meta.redirect.url')
        self.assertEqual(actual_url, prepare_url)
        self.assertEqual(actual_type, expected_type)
        self.assertEqual(actual_content, expected_content)

    def test_get_url_with_market_redirect(self):
        url = 'http://fake.url.com'
        expected_type = init.REDIRECT_META
        expected_content = 'This content is fake'
        prepare_url = 'http://object.urlunparse.with.params'
        pycurl_mock = Mock(return_value=(expected_content, None))
        prepare_url_mock = Mock(return_value=prepare_url)
        fix_redirect_url = 'https://play.google.com/store/apps/meta_redirect_url'
        fix_market_url_mock = Mock(return_value=fix_redirect_url)
        with patch('source.lib.make_pycurl_request', pycurl_mock),\
             patch('source.lib.logger', Mock()), \
             patch('source.lib.prepare_url', prepare_url_mock),\
             patch('source.lib.check_for_meta', Mock(return_value='market://meta_redirect_url')),\
             patch('source.lib.fix_market_url', fix_market_url_mock):
            actual_url, actual_type, actual_content = init.get_url(url, timeout=8)
        prepare_url_mock.assert_called_once_with(fix_redirect_url)
        self.assertEqual(actual_url, prepare_url)
        self.assertEqual(actual_type, expected_type)
        self.assertEqual(actual_content, expected_content)


    def test_prepare_url_with_none_url(self):
        url = None
        waiting_result = None
        result = init.prepare_url(url)
        self.assertEqual(waiting_result, result)

    def test_prepare_url_url_is_ok(self):
        url = 'https://github.com/'
        result = init.prepare_url(url)
        self.assertEqual(result, url)

    def test_prepare_url_exception(self):
        url = 'https://github.com/'
        mock_netloc = mock.Mock()
        mock_netloc.encode.side_effect = UnicodeError
        mock_urlunparse = mock.Mock(return_value=url)
        with mock.patch("source.lib.urlparse", mock.Mock(return_value=(None, mock_netloc, None, None, None, None))),\
             mock.patch("source.lib.quote", mock.Mock()),\
             mock.patch("source.lib.quote_plus", mock.Mock()),\
             mock.patch("source.lib.urlunparse", mock_urlunparse):
            result = init.prepare_url(url)
            self.assertEqual(result, url)
