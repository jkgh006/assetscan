import Queue
import threading


class ThreadPool(object):
    def __init__(self, thread_num):
        self.task_queue = Queue.Queue()
        self.threads = []
        self.__init_thread_pool(thread_num)

    def __init_thread_pool(self,thread_num):
        for i in range(thread_num):
            worker = Worker(self.task_queue)
            worker.setDaemon(True)
            worker.start()
            self.threads.append(worker)

    def add_task(self, func, *args):
        self.task_queue.put((func, args))

    def wait_all_complete(self):
        self.task_queue.join()
        self._terminate_workers()

    def force_complete(self):
        self.clear_tasks()
        self._terminate_workers()

    def clear_tasks(self):
        while not self.task_queue.empty():
            self.task_queue.get_nowait()
            self.task_queue.task_done()
    def _terminate_workers(self):
        for worker in self.threads:
            worker.terminate()
class Worker(threading.Thread):
    def __init__(self, task_queue):
        super(Worker, self).__init__()
        self.task_queue = task_queue
        self.stop = False

    def run(self):
        max_len = 64
        while not self.stop:
            try:
                do, args = self.task_queue.get(timeout=1)
                args_desc = str(args)
                if len(args_desc) > max_len:
                    pass
                try:
                    do(*args)
                except:
                    pass
                if self.stop:
                    pass
                self.task_queue.task_done()
            except:
                pass
    def terminate(self):
        self.stop = True