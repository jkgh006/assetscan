# -*- coding:utf-8 -*-
import time
from common.logger.log_util import LogUtil as logging
logger = logging.getLogger(__name__)
class TaskStatus:
    START = 0x01
    RUNNING = 0x02
    ERROR = 0x03
    FINISHED = 0x04

class TaskCenter(object):

    @classmethod
    def register(cls,statusqueue,tskname):
        taskinfo = {}
        for tname in tskname:
            taskinfo.update({tname:TaskStatus.START})
        if not statusqueue.empty():
            sts = statusqueue.get(True)
            sts.update(taskinfo)
            statusqueue.put(sts)
        else:
            statusqueue.put(taskinfo)

    @classmethod
    def run(cls,statusqueue):
        finished = False
        while not finished:
            time.sleep(0.2)
            if not statusqueue.empty():
                status = statusqueue.get(True)
                rs = [x for x in status.values() if x == TaskStatus.FINISHED]
                if len(rs) == len(status):
                    finished = True
                    logger.info("All tasks({0}) completed".format(",".join(status.keys())))
                statusqueue.put(status)

    @classmethod
    def update_task_status(cls,statusqueue,taskname,taskstatus):
        if not statusqueue.empty():
            status = statusqueue.get(True)
            if taskname in status.keys():
                status.update({taskname:taskstatus})
            statusqueue.put(status)

    @classmethod
    def task_is_finished(cls,statusqueue,taskname):
        if not statusqueue.empty():
            status = statusqueue.get(True)
            statusqueue.put(status)
        else:
            status = {}
        if status.get(taskname,None) ==  TaskStatus.FINISHED:
            return True
        else:
            return False
