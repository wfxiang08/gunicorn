# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import os
import signal
import time
import traceback
from random import randint
from multiprocessing import RLock
from multiprocessing.sharedctypes import Array, Value
import socket
import sys

from colorama import Fore
import zmq
import gevent
from gevent.pool import Pool

from gunicorn_zmq import util
from gunicorn_zmq.workers.workertmp import WorkerTmp
from gunicorn_zmq.reloader import Reloader
from gunicorn_zmq.six import MAXSIZE


if sys.platform == "darwin":
    os.environ['EVENT_NOKQUEUE'] = "1"

"""
    gevent和zeromq的结合

    专注于处理后台基于zeromq的RPC, 不负责处理http请求
"""

ALREADY_HANDLED = object()

class GeventWorker(object):

    SIGNALS = [getattr(signal, "SIG%s" % x) for x in "ABRT HUP QUIT INT TERM USR1 USR2 WINCH CHLD".split()]
    PIPE = []

    def __init__(self, age, ppid, socket, app, timeout, cfg, log):
        """\
        This is called pre-fork so it shouldn't do anything to the
        current process. If there's a need to make process wide
        changes you'll want to do that in ``self.init_process()``.
        """
        self.age = age
        self.ppid = ppid # 记住ppid作用?

        self.socket = socket

        # 要指定的任务, 例如: uwsgi#application
        self.app = app

        self.timeout = timeout
        self.cfg = cfg
        # self.booted = False
        self.aborted = False
        self.reloader = None

        self.nr = 0
        jitter = randint(0, cfg.max_requests_jitter)
        self.max_requests = cfg.max_requests + jitter or MAXSIZE
        self.alive = True
        self.log = log
        self.tmp = WorkerTmp(cfg)

        # 告诉Master当前的URL是什么，在被堵住的情况下，可以不通知
        lock = RLock()
        self.current_url = Array('c', 200, lock=lock)
        self.booted = Value('i', 0)

        self.worker_connections = self.cfg.worker_connections


    def __str__(self):
        return "<Worker %s>" % self.pid

    @property
    def pid(self):
        return os.getpid()



    def load_server(self):
        """
            加载指定的 server, 例如: accounts.server
        """
        try:
            self.rpc = self.app.server()
        except SyntaxError as e:
            if not self.cfg.reload:
                raise

            self.log.exception(e)

            exc_type, exc_val, exc_tb = sys.exc_info()
            self.reloader.add_extra_file(exc_val.filename)

            tb_string = traceback.format_exc(exc_tb)
            self.rpc = util.make_fail_app(tb_string)

    def init_signals(self):
        # reset signaling
        [signal.signal(s, signal.SIG_DFL) for s in self.SIGNALS]

        # init new signaling
        signal.signal(signal.SIGQUIT, self.handle_quit)
        signal.signal(signal.SIGTERM, self.handle_exit)
        signal.signal(signal.SIGINT, self.handle_quit)
        signal.signal(signal.SIGWINCH, self.handle_winch)
        signal.signal(signal.SIGUSR1, self.handle_usr1)

        signal.signal(signal.SIGABRT, self.handle_abort)

        # Don't let SIGTERM and SIGUSR1 disturb active requests
        # by interrupting system calls
        if hasattr(signal, 'siginterrupt'):  # python >= 2.6
            signal.siginterrupt(signal.SIGTERM, False)
            signal.siginterrupt(signal.SIGUSR1, False)

    def handle_usr1(self, sig, frame):
        self.log.reopen_files()

    # 通过信号控制 self.alive, 然后控制进程的状态
    def handle_exit(self, sig, frame):
        """
            比较Gracefully退出
            :param sig:
            :param frame:
            :return:
        """
        self.alive = False


    def handle_quit(self, sig, frame):
        self.alive = False
        # worker_int callback
        self.cfg.worker_int(self)
        time.sleep(0.1)
        sys.exit(0)

    def handle_abort(self, sig, frame):
        """
            强制退出
        :param sig:
        :param frame:
        :return:
        """
        self.alive = False
        self.cfg.worker_abort(self)
        sys.exit(1)

    def timeout_ctx(self):
        return gevent.Timeout(self.cfg.keepalive, False)

    def handle(self, listener, client, addr):
        pass




    def patch(self):
        from gevent import monkey
        monkey.noisy = False

        # if the new version is used make sure to patch subprocess
        if gevent.version_info[0] == 0:
            monkey.patch_all()
        else:
            monkey.patch_all(subprocess=True)

        # patch sockets
        self.sockets = socket(self.socket.FAMILY, _socket.SOCK_STREAM, _sock=self.socket)

    def notify(self):
        """\
        Your worker subclass must arrange to have this method called
        once every ``self.timeout`` seconds. If you fail in accomplishing
        this task, the master process will murder your workers.
        """
        self.tmp.notify()

        if self.ppid != os.getppid():
            self.log.info("Parent changed, shutting down: %s", self)
            sys.exit(0)



    def run(self):
        servers = []

        # 在自进程中要做什么事情呢?
        ssl_args = {}




        if self.cfg.is_ssl:
            ssl_args = dict(server_side=True, **self.cfg.ssl_options)

        # 假定只有一个 sockets
        self.socket.setblocking(1)

        # 控制同一个进程内部的并发度
        pool = Pool(self.worker_connections)

        server = self.server_class(
                s, application=self.rpc, spawn=pool, log=self.log,
                handler_class=self.wsgi_handler, environ=environ,
                **ssl_args)

        server.start()

        try:
            # 告诉主服务，当前进程是否还活着
            while self.alive:
                self.notify()
                gevent.sleep(1.0)

        except KeyboardInterrupt:
            pass
        except:
            for server in servers:
                try:
                    server.stop()
                except:
                    pass
            raise

        try:
            # Stop accepting requests
            for server in servers:
                if hasattr(server, 'close'):  # gevent 1.0
                    server.close()
                if hasattr(server, 'kill'):  # gevent < 1.0
                    server.kill()

            # Handle current requests until graceful_timeout
            ts = time.time()
            while time.time() - ts <= self.cfg.graceful_timeout:
                accepting = 0
                for server in servers:
                    if server.pool.free_count() != server.pool.size:
                        accepting += 1

                # if no server is accepting a connection, we can exit
                if not accepting:
                    return

                self.notify()
                gevent.sleep(1.0)

            # Force kill all active the handlers
            self.log.warning("Worker graceful timeout (pid:%s)" % self.pid)
            [server.stop(timeout=1) for server in servers]
        except:
            pass

    def handle_request(self, *args):
        try:
            super(GeventWorker, self).handle_request(*args)
        except gevent.GreenletExit:
            pass
        except SystemExit:
            pass

    def init_process(self):
        """
            只支持 gevent 1.0以上的版本
        """
        # monkey patch here
        self.patch()

        # reinit the hub
        from gevent import hub
        hub.reinit()

        """
        If you override this method in a subclass, the last statement
        in the function should be to call this method with
        super(MyWorkerClass, self).init_process() so that the ``run()``
        loop is initiated.
        """

        # start the reloader
        if self.cfg.reload:
            # 一般Debug时才选择使用 reload
            def changed(fname):
                self.log.info("Worker reloading: %s modified", fname)
                os.kill(self.pid, signal.SIGQUIT)
            self.reloader = Reloader(callback=changed)
            self.reloader.start()

        # set environment' variables
        if self.cfg.env:
            for k, v in self.cfg.env.items():
                os.environ[k] = v

        util.set_owner_process(self.cfg.uid, self.cfg.gid)

        # Reseed the random number generator
        util.seed()

        # For waking ourselves up
        self.PIPE = os.pipe()
        for p in self.PIPE:
            util.set_non_blocking(p)
            util.close_on_exec(p)

        # Prevent fd inheritance
        util.close_on_exec(self.socket)
        util.close_on_exec(self.tmp.fileno())

        self.log.close_on_exec()

        self.init_signals()

        self.cfg.post_worker_init(self)

        t1 = time.time()

        self.log.info(Fore.MAGENTA + "----> Starting Load uwsgi, with age: %s" + Fore.RESET, self.age)
        self.load_server() # 加载wsgi
        t2 = time.time()
        self.log.info(Fore.MAGENTA + "----> End Load uwsgi, with age: %s, Elapsed: %.3f" + Fore.RESET, self.age, t2 - t1)


        # Enter main run loop
        # self.booted = True
        self.booted.value = 1
        self.run()

    def run_server(self, ident):
        # 在同一个进程内部启动多个worker?
        socket = zmq.Context().socket(zmq.REQ)
        socket.identity = "rpc-server-%s" % (self.pid, ident)

        socket.connect("ipc://backend.ipc")
        socket.send(b"READY")

        while True:
            address, _, request = socket.recv_multipart()
            self.rpc(request)
            socket.send_multipart([address, b"", b"OK"])