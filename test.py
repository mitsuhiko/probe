from libprobe import probe_website, magic_probe


def print_results(caption, url, results):
    print 'Results for %s [%s]' % (caption, url)
    for result in results:
        print '>', result


def runtest(caption, url, *args, **kwargs):
    print_results(caption, url, probe_website(url, *args, **kwargs))


def main():
    url, results = magic_probe('http://djangoproject.com/')
    print_results('Django', url, results)

    runtest('Django', 'https://www.djangoproject.com/',
            '/admin/')
    runtest('Giantbomb', 'http://www.giantbomb.com/',
            '/admin/')
    runtest('Shinpaku', 'http://www.shinpaku.com/')
    runtest('Disus', 'http://www.disqus.com/')
    runtest('Mozilla Addons', 'https://addons.mozilla.org/')
    runtest('Djangosites', 'http://www.djangosites.org/')
    runtest('Pylons', 'http://pylonsproject.org/')
    runtest('Flask', 'http://flask.pocoo.org/',
            url_with_slash='/community/')
    runtest('BF3', 'http://bf3.immersedcode.org/',
            url_with_slash='/twitter/', url_without_slash='/page/2')
    runtest('php.net', 'http://www.php.net/')
    runtest('Bitbucket', 'http://bitbucket.org/',
            form_url='https://bitbucket.org/account/signup/?plan=5_users')
    runtest('alexgaynor', 'http://alexgaynor.net/')
    runtest('reddit', 'http://www.reddit.com/',
            url_without_slash='/r/leagueoflegends')


if __name__ == '__main__':
    main()
