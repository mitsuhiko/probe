# -*- coding: utf-8 -*-
"""
    libprobe
    ~~~~~~~~

    Probes remote servers and attempts to guess their software.

    :copyright: (c) 2011 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
from __future__ import with_statement
import re
from StringIO import StringIO
from Cookie import SimpleCookie
import httplib
import urllib
import urllib2
import difflib
import urlparse
import posixpath


_missing = object()
_input_re = re.compile(r'<input\s+([^>]+)>(?sm)')
_label_re = re.compile(r'<input\s+([^>]+)>(?sm)')
_attr_re = re.compile(r'(\S+)\s*=\s*((?:"[^"]*")|(?:\'[^\']\'))(?sm)')
_link_re = re.compile(r'<a\s+[^>]*?href=((?:"[^"]*")|(?:\'[^\']\'))(?sm)')


def parse_html_attributes(string):
    rv = {}
    for match in _attr_re.finditer(string):
        attr, value = match.groups()
        if value[0] in '"\'':
            value = value[1:-1]
        rv[attr] = value
    return rv


class Indicator(object):

    def __init__(self, callback, score=None):
        self.callback = callback
        self.score = score
        self.description = callback.__doc__

    @property
    def name(self):
        rv = self.callback.__name__
        if rv.startswith('probe_'):
            rv = rv[6:]
        return rv


class cached_property(object):

    def __init__(self, func):
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__
        self.func = func

    def __get__(self, obj, type=None):
        if obj is None:
            return self
        rv = obj.__dict__.get(self.__name__, _missing)
        if rv is not _missing:
            return rv
        obj.__dict__[self.__name__] = rv = self.func(obj)
        return rv


class Response(object):

    def __init__(self, con):
        if con is None:
            self.con = self.resp = None
            self.status = 500
            self.headers = {}
            self.reason = 'CONNECTION PROBLEM'
        else:
            self.con = con
            self.resp = resp = con.getresponse()
            self.status = resp.status
            self.reason = resp.reason
            self.headers = dict((k.lower(), v) for k, v in resp.getheaders())

    @cached_property
    def body(self):
        if self.resp is None:
            return ''
        return self.resp.read()

    def __del__(self):
        self.close()

    def close(self):
        if self.con is not None:
            self.con.close()
            self.con = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.close()


class Prober(object):
    name = 'Generic'

    def __init__(self, config, cache):
        self.config = config
        self._request_cache = cache

    def make_connection(self, scheme, netloc):
        if scheme == 'http':
            cls = httplib.HTTPConnection
        elif scheme == 'https':
            cls = httplib.HTTPSConnection
        else:
            raise RuntimeError('Totally unsupported scheme %r' % scheme)
        if ':' in netloc:
            netloc, port = netloc.rsplit(':', 1)
            port = int(port)
        else:
            port = scheme == 'http' and 80 or 443
        con = cls(netloc, port, timeout=self.config.timeout)
        return con

    def make_headers(self, reference_headers=None):
        headers = reference_headers
        if headers is None:
            headers = {}
        headers['User-Agent'] = self.config.user_agent
        return headers

    def make_request(self, url, method='GET', query=None, data=None,
                     headers=None):
        url = urlparse.urljoin(self.config.url, url)
        pieces = urlparse.urlsplit(url)
        local_url = pieces.path
        if pieces.query or query:
            local_url += '?' + pieces.query
            if query:
                if not local_url.endswith('?'):
                    local_url += '&'
                local_url += urllib.urlencode(query)
        headers = self.make_headers(headers)
        body = None
        if data is not None:
            body = StringIO(urllib.urlparse(data))
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        key = (url, local_url, method, tuple(headers.items()))
        if key in self._request_cache:
            return self._request_cache[key]

        try:
            con = self.make_connection(pieces.scheme, pieces.netloc)
            con.request(method, local_url, body, headers)
            rv = Response(con)
        except IOError:
            rv = Response(None)
        self._request_cache[key] = rv
        return rv

    def get_indicators(self):
        return []

    def check(self):
        score = 0.0
        hits = []
        for indicator in self.get_indicators():
            rv = indicator.callback()
            if rv:
                if indicator.score is None:
                    this_score = rv
                else:
                    this_score = indicator.score
                hits.append((indicator, this_score))
                score += this_score
        return Result(score, self, hits)

    def __repr__(self):
        return '%s()' % self.__class__.__name__


class DjangoProber(Prober):
    name = 'Django'

    def probe_reason_capitalization(self):
        """The status reason has the correct capitalization"""
        rv = self.make_request(self.config.missing_url + '/')
        return rv.status == 404 and rv.reason == 'NOT FOUND'

    def probe_redirects(self):
        """The default redirecting behavior is there"""
        rv = self.make_request(self.config.missing_url.rstrip('/'))
        return rv.status in (301, 302) and rv.body == '' and \
            rv.headers.get('location', '').startswith(('http://', 'https://'))

    def probe_admin(self):
        """An admin interface was detected"""
        rv = self.make_request('admin/')
        return rv.status == 200 and 'Django' in rv.body

    def probe_admin_media(self):
        """Admin interface CSS files were found"""
        for url in 'media/admin/css/login.css', 'adminmedia/admin/css/login.css':
            rv = self.make_request(url)
            if rv.status == 200:
                break
        else:
            scheme, netloc, path = urlparse.urlsplit(self.config.url)[:3]
            path = posixpath.join(path, 'media/admin/css/login.css')
            if netloc.startswith('www.'):
                netloc = netloc[4:]
            if scheme == 'https':
                scheme = 'http'
            url = urlparse.urlunsplit((scheme, 'media.' + netloc, path, '', ''))
            rv = self.make_request(url)
        if rv.status == 200:
            return 'base.css' in rv.body
        return False

    def probe_csrf_middleware(self):
        """The CSRF middleware was detected"""
        if self.config.form_url is None:
            return
        rv = self.make_request(self.config.form_url)
        return "<input type='hidden' name='csrfmiddlewaretoken'" in rv.body

    def probe_debug_404(self):
        """A debug 404 page was found"""
        rv = self.make_request(self.config.missing_url)
        return '<h1>Page not found <span>(404)</span></h1>' in rv.body and \
               ("You're seeing this error because you have "
                "<code>DEBUG = True</code>") in rv.body

    def probe_csrf_cookie(self):
        """A new CSRF token was found"""
        for url in self.config.url, self.config.form_url:
            if url is None:
                continue
            rv = self.make_request(url)
            if rv.status != 200:
                continue
            cookie = rv.headers.get('set-cookie')
            if cookie is not None and \
               'csrftoken' in cookie:
                return True
        return False

    def probe_content_type(self):
        """The correct default charset was detected"""
        rv = self.make_request(self.config.url)
        return rv.headers.get('content-type') == 'text/html; charset=utf-8'

    def probe_form_rendering(self):
        """The default form rendering naming was detected"""
        if self.config.form_url is None:
            return 0.0
        rv = self.make_request(self.config.form_url)
        if rv.status != 200:
            return 0.0
        found_label = found_input = False
        inputs_found = set()

        for match in _input_re.finditer(rv.body):
            attrs = parse_html_attributes(match.group())
            if 'id' in attrs and 'name' in attrs and \
               attrs['id'] == 'id_' + attrs['name']:
                inputs_found.add(attrs['id'])
                found_input = True

        for match in _label_re.finditer(rv.body):
            attrs = parse_html_attributes(match.group())
            if 'for' in attrs and attrs['for'] in inputs_found:
                found_input = True
                break

        return (found_label + found_input) * 0.25

    def get_indicators(self):
        return [
            Indicator(self.probe_redirects, 0.25),
            Indicator(self.probe_admin, 1.0),
            Indicator(self.probe_admin_media, 1.0),
            Indicator(self.probe_csrf_middleware, 0.8),
            Indicator(self.probe_debug_404, 1.0),
            Indicator(self.probe_csrf_cookie, 0.8),
            Indicator(self.probe_content_type, 0.1),
            Indicator(self.probe_reason_capitalization, 0.1),
            Indicator(self.probe_form_rendering)
        ]


class PyramidProber(Prober):
    name = 'Pyramid / Pylons'

    def probe_reason_capitalization(self):
        """The status reason has the correct capitalization"""
        rv = self.make_request(self.config.missing_url)
        return rv.status == 404 and rv.reason == 'Not Found'

    def probe_content_type(self):
        """The correct default charset was detected"""
        rv = self.make_request(self.config.url)
        return rv.headers.get('content-type') == 'text/html; charset=UTF-8'

    def probe_404_content_length(self):
        """404 page has a content length"""
        rv = self.make_request(self.config.missing_url)
        return 'content-length' in rv.headers

    def probe_slash_behavior(self):
        """The pyramid 'don't care about slashes' behavior was detected"""
        if self.config.url_without_slash is None:
            return False
        rv1 = self.make_request(self.config.url_without_slash)
        if rv1.status != 200:
            return False
        rv2 = self.make_request(self.config.url_without_slash + '/')
        if rv2.status != 200:
            return False
        return difflib.get_close_matches(rv1.body, [rv2.body], 1, 0.8) != []

    def get_indicators(self):
        return [
            Indicator(self.probe_reason_capitalization, 0.1),
            Indicator(self.probe_content_type, 0.1),
            Indicator(self.probe_404_content_length, 0.1),
            Indicator(self.probe_slash_behavior, 0.1)
        ]


class WerkzeugProber(Prober):
    name = 'Werkzeug / Flask'

    def probe_reason_capitalization(self):
        """The status reason has the correct capitalization"""
        rv = self.make_request(self.config.missing_url)
        return rv.status == 404 and rv.reason == 'NOT FOUND'

    def probe_content_type(self):
        """The correct default charset was detected"""
        rv = self.make_request(self.config.url)
        return rv.headers.get('content-type') == 'text/html; charset=utf-8'

    def probe_securecookie(self):
        """Something that looks like a securecookie was detected"""
        rv = self.make_request(self.config.url)
        setcookie = rv.headers.get('set-cookie')
        if setcookie is None:
            return False
        if not '; Path=' in setcookie:
            return False
        cookie = SimpleCookie(setcookie)
        for key, morsel in cookie.items():
            if not '?' in morsel.value:
                continue
            try:
                morsel.value.split('?')[0].decode('base64')
                return True
            except Exception:
                return False
        return False

    def probe_connection_close(self):
        """Connection close behavior detected"""
        rv = self.make_request(self.config.url)
        return rv.headers.get('connection') == 'close'

    def probe_easteregg(self):
        """The Werkzeug easteregg was found"""
        rv = self.make_request(self.config.url + '?macgybarchakku')
        return rv.status == 200 and \
               'the Swiss Army knife of Python web development' in rv.body

    def probe_redirect_missing_slash(self):
        """The missing slash redirection was detected"""
        if self.config.url_with_slash is None:
            return False
        rv = self.make_request(self.config.url_with_slash.rstrip('/'))
        if rv.status != 301:
            return False
        return 'content-length' in rv.headers and \
               rv.headers.get('location', '') \
                    .startswith(('http://', 'https://')) and \
               '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">' in rv.body and \
               '<h1>Redirecting...</h1>' in rv.body

    def probe_404_on_trailing_slash(self):
        """The extra slash 404 error was detected"""
        if self.config.url_without_slash is None:
            return False
        rv = self.make_request(self.config.url_without_slash)
        if rv.status != 200:
            return False
        rv = self.make_request(self.config.url_without_slash + '/')
        return rv.status == 404

    def get_indicators(self):
        return [
            Indicator(self.probe_reason_capitalization, 0.1),
            Indicator(self.probe_content_type, 0.1),
            Indicator(self.probe_securecookie, 0.3),
            Indicator(self.probe_connection_close, 0.1),
            Indicator(self.probe_easteregg, 1.0),
            Indicator(self.probe_redirect_missing_slash, 1.0),
            Indicator(self.probe_404_on_trailing_slash, 0.1)
        ]


class PHPProber(Prober):
    name = 'PHP'

    def probe_x_powered_by(self):
        """PHP header detected"""
        rv = self.make_request(self.config.url)
        return rv.headers.get('x-powered-by', '').startswith('PHP/')

    def probe_easter_egg(self):
        """PHP easter egg detected"""
        rv = self.make_request(self.config.url, query={'': 'PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000'})
        return "PHP Credits" in rv.body

    def get_indicators(self):
        return [
            Indicator(self.probe_x_powered_by, 1.0),
            Indicator(self.probe_easter_egg, 1.0)
        ]


class Result(object):

    def __init__(self, score, prober, hits=None):
        self.score = score
        self.prober = prober
        if hits is None:
            hits = []
        self.hits = hits

    def __repr__(self):
        return '%s(score=%s, prober=%s, hits=%s)' % (
            self.__class__.__name__,
            self.score,
            self.prober,
            [x[0].name for x in self.hits]
        )


class Config(dict):
    default_user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; ' \
                         'rv:6.0a2) Gecko/20110604 Firefox/6.0a2'

    @property
    def timeout(self):
        return self['timeout']

    @property
    def url(self):
        return self['url']

    @property
    def form_url(self):
        if self['form_url'] is not None:
            return urlparse.urljoin(self.url, self['form_url'])

    @property
    def url_with_slash(self):
        if self['url_with_slash'] is not None:
            return urlparse.urljoin(self.url, self['url_with_slash'])

    @property
    def url_without_slash(self):
        if self['url_without_slash'] is not None:
            return urlparse.urljoin(self.url, self['url_without_slash'])

    @property
    def missing_url(self):
        return self.get('missing_url', 'totally-not-existing-url')

    @property
    def user_agent(self):
        return self.get('user_agent', self.default_user_agent)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, dict.__repr__(self))


all_probers = [DjangoProber, PyramidProber, WerkzeugProber, PHPProber]


def iter_probers(config):
    cache = {}
    for prober in all_probers:
        yield prober(config, cache)


def probe_website(url, form_url=None, url_with_slash=None,
                  url_without_slash=None, timeout=None, config=None):
    config = Config(config or {}, url=url, form_url=form_url,
        url_with_slash=url_with_slash, url_without_slash=url_without_slash,
        timeout=timeout)
    results = []
    for prober in iter_probers(config):
        rv = prober.check()
        if rv.score > 0.0:
            results.append(rv)
    results.sort(key=lambda x: -x.score)
    return results


def magic_probe(start_url, timeout=None, config=None):
    form_url = url_with_slash = url_without_slash = None
    resp = urllib2.urlopen(start_url, timeout=timeout)
    url = resp.geturl()

    for link in _link_re.findall(resp.read()):
        if link[0] in '"\'':
            link = link[1:-1]
        link = urlparse.urljoin(url, link)
        if urlparse.urlsplit(link).netloc == urlparse.urlsplit(url).netloc:
            if url_with_slash is None and link.endswith('/') and link != url:
                url_with_slash = link
            elif url_without_slash is None and not link.endswith('/'):
                url_without_slash = link
            if form_url is None:
                try:
                    form_resp = urllib.urlopen(link).read()
                    if '<form' in form_resp:
                        form_url = link
                except IOError:
                    pass

    return url, probe_website(url, form_url, url_with_slash,
                              url_without_slash, timeout, config)
