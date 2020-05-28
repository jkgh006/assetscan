# -*- coding:utf-8 -*-
from urllib import urlencode
import urllib3
from thirdparty.connection.exceptions import ConnectionError
urllib3.disable_warnings()

class HttpUtil():
    def __init__(self):
        self.pool = urllib3.PoolManager()
        self.default_headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',"Cookie":"rememberMe=xx"}
    def request(self, url, params=None,body=None, timeout=None,headers={},redirect=False,**kwargs):
        if params:
            url = '%s?%s' % (url, urlencode(params))
        if body:
            method = "POST"
        else:
            method = "GET"
        try:
            kw = {}
            if timeout:
                kw['timeout'] = timeout
            if not isinstance(url, str):
                url = url.encode('utf-8')
            if not isinstance(method, str):
                method = method.encode('utf-8')
            if redirect:
                retries = 3
            else:
                retries = False
            headers.update(self.default_headers)
            response = self.pool.request(method, url, body, retries=retries,redirect=redirect, headers=headers,timeout=urllib3.Timeout(connect=timeout, read=2.0),**kwargs)
            response.content = response.data
            response.status_code = response.status
            response.resp_headers = response.getheaders()
        except Exception as e:
            raise ConnectionError('N/A', str(e), e)
        return response