# -*- coding:utf-8 -*-
import threading
from common.logger.log_util import LogUtil as logging
from common.utils import md5_string

logger = logging.getLogger(__name__)
mu = threading.Lock()

class PLGSTATE:
    NORUN = 0x01
    RUNNING = 0x10
    FINISHED = 0x11

class ReportManage(object):

    def __init__(self):
        self._results = None
        self._output_queue = None
        self._unique_hash = None

    @property
    def results(self):
        return self._results

    @property
    def unique_hash(self):
        return self._unique_hash

    @property
    def output_queue(self):
        return self._output_queue

    @classmethod
    def instance(self):
        rpt = ReportManage()
        rpt._results = []
        rpt._unique_hash = []
        rpt._output_queue = []
        return rpt


class IPlugin(object):

    def __init__(self, knowledgebase=None):
        self._id = None
        self._name = None
        self._level = 1
        self._cookies = ""
        self._proxies = {}
        self._result_manage = ReportManage.instance()
        self._state = PLGSTATE.NORUN


    @property
    def state(self):
        return self._state

    @property
    def id(self):
        if self._id is None:
            raise Exception("must be set plugin's id ")
        return self._id

    @property
    def name(self):
        if self._name is None:
            raise Exception("must be set plugin's name ")
        return self._name

    @property
    def cookies(self):
        return self._cookies

    @cookies.setter
    def cookies(self, value):
        self._cookies = value

    @property
    def proxies(self,type=1):
        return self._proxies

    #('http', ('127.0.0.1', 9050), ('username', 'password')),('socks5', ('127.0.0.1', 1080))
    """
    'socks5': pycurl.PROXYTYPE_SOCKS5
    'socks4': pycurl.PROXYTYPE_SOCKS4
    'http': pycurl.PROXYTYPE_HTTP
    'https': pycurl.PROXYTYPE_HTTP
    """
    @proxies.setter
    def proxies(self, value):
        self._proxies = value

    @property
    def result_manage(self):
        return self._result_manage

    @result_manage.setter
    def result_manage(self,value):
        self._result_manage = value

    @property
    def level(self):
        return self._level

    def _report(self,package,unique=[]):
        if isinstance(package,list) or isinstance(package,tuple):
            if unique:
                rsdiff = list(set(unique) - set(range(len(package))))
                if rsdiff:
                    raise Exception('Unknown filter index({0})'.format(rsdiff))
            else:
                unique = range(len(package))
            filters = [str(package[x]) for x in unique]
            unique_hash = md5_string(",".join(filters))
        elif isinstance(package,dict):
            filters = {}
            if unique:
                rsdiff = list(set(unique)-set(package.keys()))
                if rsdiff:
                    raise Exception('Unknown filter fields({0})'.format(rsdiff))
            else:
                unique = range(len(package.keys()))
            for x in unique:
                filters.update({x:package.get(x)})

            unique_hash = md5_string(",".join([ str(x) for x in filters.values()]))
        else:
            raise Exception('unique Only support list，tuple，dict')

        if self.result_manage is None:
            self.result_manage = ReportManage.instance()

        if mu.acquire(True):
            if not unique_hash in self.result_manage.unique_hash:
                self.result_manage.unique_hash.append(unique_hash)
                self.result_manage.results.append(filters)
                self.result_manage.output_queue.append(package)
            mu.release()

    def _run(self, *args,**kwargs):
        raise Exception('unimplemented method')

    def _store(self, *args,**kwargs):
        raise Exception('unimplemented method')

    def _create_report(self, *args,**kwargs):
        raise Exception('unimplemented method')

    def cmd_run(self, *args,**kwargs):
        self._state = PLGSTATE.RUNNING
        try:
            t = threading.Thread(target=self._store)
            t.start()
            self._run(*args,**kwargs)
        except:
            import traceback
            msg = traceback.format_exc()
            logger.warn(msg)
        self._state = PLGSTATE.FINISHED

    def __str__(self):
        return 'plugin(plg_id=%d, name=%s)' % (self.id, self._name)

