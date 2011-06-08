# -*- coding: utf-8 -*-
"""
    webprobe
    ~~~~~~~~

    Web application for probing other applications.

    :copyright: (c) Copyright 2011 by Armin Ronacher.
    :license: see LICENSE for more details.
"""
import urlparse
from flask import Flask, request, abort, render_template, \
     get_template_attribute
import libprobe


app = Flask(__name__)
app.debug = True


@app.template_filter('hostname')
def get_hostname(url):
    return urlparse.urlparse(url).netloc.split(':')[0]


def make_url(url):
    if not urlparse.urlparse(url).scheme:
        url = 'http://' + url
    return url


def is_safe_url(url):
    return urlparse.urlparse(url).scheme in ('http', 'https')


def probe_url(url):
    url, results = libprobe.magic_probe(url, timeout=10)
    return [x for x in results if x.score > 0.3]


@app.route('/')
def index():
    results = url = None
    if request.method == 'POST':
        url = make_url(request.form['url'])
        if not is_safe_url(url):
            url = None
        else:
            results = probe_url(url)
    return render_template('index.html', url=url, results=results)


@app.route('/_probe')
def probe():
    url = request.values.get('url')
    if not url or not is_safe_url(url):
        abort(400)
    results = probe_url(url)
    func = get_template_attribute('_results.html', 'render_results')
    return func(url, results)


if __name__ == '__main__':
    app.run()
