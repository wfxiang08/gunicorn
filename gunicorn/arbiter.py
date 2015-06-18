# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.
from __future__ import print_function

import errno
import os
import random
import select
import signal
import sys
import time
import traceback

from gunicorn.errors import HaltServer, AppImportError
from gunicorn.pidfile import Pidfile
from gunicorn.sock import create_sockets
from gunicorn import util

from gunicorn import __version__, SERVER_SOFTWARE

from colorama import init
init()
from colorama import Fore, Back, Style



def get_stack_info():
    import inspect
    stacks = inspect.stack()
    results = []
    for stack in stacks:
        # filename, lineno, function, code_context, index
        func_name = "%s %s %s" % (stack[1], stack[3], stack[2])
        results.append(func_name)
    return "\n".join(results)


class Arbiter(object):
    """
    Arbiter maintain the workers processes alive. It launches or
    kills them if needed. It also manages application reloading
    via SIGHUP/USR2.
    """

    # A flag indicating if a worker failed to
    # to boot. If a worker process exist with
    # this error code, the arbiter will terminate.
    WORKER_BOOT_ERROR = 3

    # A flag indicating if an application failed to be loaded
    APP_LOAD_ERROR = 4

    START_CTX = {}

    LISTENERS = []
    WORKERS = {}
    NEW_WORKERS = {}
    PIPE = []

    # I love dynamic languages
    SIG_QUEUE = []
    SIGNALS = [getattr(signal, "SIG%s" % x) for x in "HUP QUIT INT TERM TTIN TTOU USR1 USR2 WINCH".split()]

    # 保留一般的信号
    SIG_NAMES = dict((getattr(signal, name), name[3:].lower()) for name in dir(signal) if name[:3] == "SIG" and name[3] != "_")



    def __init__(self, app):
        os.environ["SERVER_SOFTWARE"] = SERVER_SOFTWARE

        self._num_workers = None
        self.setup(app)

        self.pidfile = None
        self.worker_age = 0
        self.reexec_pid = 0

        # Master
        self.master_name = "Master"

        cwd = util.getcwd()

        # gunicorn --workers=2 test:app
        # python test:app ?
        args = sys.argv[:]
        args.insert(0, sys.executable)

        # init start context
        self.START_CTX = {
            "args": args,
            "cwd": cwd,
            0: sys.executable
        }

    def _get_num_workers(self):
        return self._num_workers

    def _set_num_workers(self, value):
        old_value = self._num_workers
        self._num_workers = value
        self.cfg.nworkers_changed(self, value, old_value)
    num_workers = property(_get_num_workers, _set_num_workers)

    def setup(self, app):
        self.app = app
        self.cfg = app.cfg
        self.log = self.cfg.logger_class(app.cfg)

        # reopen files
        if 'GUNICORN_FD' in os.environ:
            self.log.reopen_files()

        # SyncWorker
        self.worker_class = self.cfg.worker_class
        self.address = self.cfg.address
        self.num_workers = self.cfg.workers
        self.timeout = self.cfg.timeout
        self.timeout_warning = self.cfg.timeout_warning or self.timeout
        if self.timeout:
            self.timeout_warning = min(self.timeout, self.timeout_warning)
        self.proc_name = self.cfg.proc_name

        # 记录上一个很慢的URL
        self.pid_2_lasturl = {}
        try:
            from raven import Client
            self.sentry_client = Client(self.cfg.sentry_client)
        except:
            self.sentry_client = None

        self.log.debug('Current configuration:\n{0}'.format(
            '\n'.join(
                '  {0}: {1}'.format(config, value.value)
                for config, value
                in sorted(self.cfg.settings.items(),
                          key=lambda setting: setting[1]))))

        # set enviroment' variables
        if self.cfg.env:
            for k, v in self.cfg.env.items():
                os.environ[k] = v

        # 加载wsgi app(加载之后是否存在问题: 例如重新创建一个worker, 但是代码可能不会更新?)
        if self.cfg.preload_app:
            self.app.wsgi()

    def start(self):
        """\
        Initialize the arbiter. Start listening and set pidfile if needed.
        """
        self.log.info("Starting gunicorn %s", __version__)

        # 1. 保存pid
        self.pid = os.getpid()
        if self.cfg.pidfile is not None:
            self.pidfile = Pidfile(self.cfg.pidfile)
            self.pidfile.create(self.pid)

        self.cfg.on_starting(self)

        # 2. 设置signals
        self.init_signals()

        # 3. 设置listeners
        if not self.LISTENERS:
            self.LISTENERS = create_sockets(self.cfg, self.log)

        listeners_str = ",".join([str(l) for l in self.LISTENERS])
        self.log.debug("Arbiter booted")
        self.log.info("Listening at: %s (%s)", listeners_str, self.pid)
        self.log.info("Using worker: %s", self.cfg.worker_class_str)

        # check worker class requirements
        if hasattr(self.worker_class, "check_config"):
            self.worker_class.check_config(self.cfg, self.log)

        self.cfg.when_ready(self)

    def init_signals(self):
        """\
        Initialize master signal handling. Most of the signals
        are queued. Child signals only wake up the master.
        """
        # close old PIPE
        if self.PIPE:
            [os.close(p) for p in self.PIPE]

        # initialize the pipe
        self.PIPE = pair = os.pipe()
        for p in pair:
            util.set_non_blocking(p)
            util.close_on_exec(p)

        self.log.close_on_exec()

        # initialize all signals
        [signal.signal(s, self.signal) for s in self.SIGNALS]
        signal.signal(signal.SIGCHLD, self.handle_chld)

    def signal(self, sig, frame):
        if len(self.SIG_QUEUE) < 5:
            self.SIG_QUEUE.append(sig)
            self.wakeup()

    def run(self):
        "Main master loop."

        # 如何启动uwsgi进程呢?
        #
        self.start()
        util._setproctitle("master [%s]" % self.proc_name)

        self.manage_workers()

        # 正常情况下如何工作呢?
        while True:
            try:
                # 读取新的信号
                sig = self.SIG_QUEUE.pop(0) if len(self.SIG_QUEUE) else None

                # 如果没有信号，则sleep
                if sig is None:
                    # 如果没有任务就sleep
                    self.sleep()
                    self.murder_workers()
                    self.manage_workers()
                    continue

                # 如果读取到非法的，则跳过
                if sig not in self.SIG_NAMES:
                    self.log.info("Ignoring unknown signal: %s", sig)
                    continue

                # 如果读取到信号，则条用callback
                signame = self.SIG_NAMES.get(sig)
                handler = getattr(self, "handle_%s" % signame, None)
                if not handler:
                    self.log.error("Unhandled signal: %s", signame)
                    continue

                self.log.info(Fore.MAGENTA + "----> Handling signal: %s" + Fore.RESET, signame)

                # 如果存在handler, 则调用handler(处理信号)
                handler()

                # 唤醒?
                self.wakeup()

            except StopIteration:
                self.halt()
            except KeyboardInterrupt:
                self.halt()
            except HaltServer as inst:
                self.halt(reason=inst.reason, exit_status=inst.exit_status)
            except SystemExit:
                raise
            except Exception:
                self.log.info("Unhandled exception in main loop:\n%s", traceback.format_exc())
                self.stop(False)
                if self.pidfile is not None:
                    self.pidfile.unlink()
                sys.exit(-1)

    def handle_chld(self, sig, frame):
        "SIGCHLD handling"
        self.reap_workers()
        self.wakeup()

    def handle_hup(self):
        """\
        HUP handling.
        - Reload configuration
        - Start the new worker processes with a new configuration
        - Gracefully shutdown the old worker processes
        """
        self.log.info("Hang up: %s", self.master_name)
        self.reload()

    def handle_term(self):
        "SIGTERM handling"
        raise StopIteration

    def handle_int(self):
        "SIGINT handling"
        self.stop(False)
        raise StopIteration

    def handle_quit(self):
        "SIGQUIT handling"
        self.stop(False)
        raise StopIteration

    def handle_ttin(self):
        """\
        SIGTTIN handling.
        Increases the number of workers by one.
        """
        self.num_workers += 1
        self.manage_workers()

    def handle_ttou(self):
        """\
        SIGTTOU handling.
        Decreases the number of workers by one.
        """
        if self.num_workers <= 1:
            return
        self.num_workers -= 1
        self.manage_workers()

    def handle_usr1(self):
        """\
        SIGUSR1 handling.
        Kill all workers by sending them a SIGUSR1
        """
        self.log.reopen_files()
        self.kill_workers(signal.SIGUSR1)

    def handle_usr2(self):
        """\
        SIGUSR2 handling.
        Creates a new master/worker set as a slave of the current
        master without affecting old workers. Use this to do live
        deployment with the ability to backout a change.
        """
        self.reexec()

    def handle_winch(self):
        "SIGWINCH handling"
        if self.cfg.daemon:
            self.log.info("graceful stop of workers")
            self.num_workers = 0
            # 停止所有的workers
            self.kill_workers(signal.SIGTERM)
        else:
            self.log.debug("SIGWINCH ignored. Not daemonized")

    def wakeup(self):
        """\
        Wake up the arbiter by writing to the PIPE
        """
        try:
            os.write(self.PIPE[1], b'.')
        except IOError as e:
            if e.errno not in [errno.EAGAIN, errno.EINTR]:
                raise

    def halt(self, reason=None, exit_status=0):
        """ halt arbiter """
        self.stop()
        self.log.info("Shutting down: %s", self.master_name)
        if reason is not None:
            self.log.info("Reason: %s", reason)
        if self.pidfile is not None:
            self.pidfile.unlink()
        self.cfg.on_exit(self)
        sys.exit(exit_status)

    def sleep(self):
        """\
        Sleep until PIPE is readable or we timeout.
        A readable PIPE means a signal occurred.
        """
        try:
            ready = select.select([self.PIPE[0]], [], [], 1.0)
            if not ready[0]:
                return
            # 如果PIPE[0]一直为1, 则一直等待
            while os.read(self.PIPE[0], 1):
                pass
        except select.error as e:
            if e.args[0] not in [errno.EAGAIN, errno.EINTR]:
                raise
        except OSError as e:
            if e.errno not in [errno.EAGAIN, errno.EINTR]:
                raise
        except KeyboardInterrupt:
            sys.exit()

    def stop(self, graceful=True):
        """\
        Stop workers

        :attr graceful: boolean, If True (the default) workers will be
        killed gracefully  (ie. trying to wait for the current connection)
        """
        self.LISTENERS = []
        sig = signal.SIGTERM
        if not graceful:
            sig = signal.SIGQUIT

        limit = time.time() + self.cfg.graceful_timeout

        # 首先graceful关闭所有的worker, 如果失败，则强制执行
        # instruct the workers to exit
        self.kill_workers(sig)
        # wait until the graceful timeout
        while self.WORKERS and time.time() < limit:
            time.sleep(0.1)

        self.kill_workers(signal.SIGKILL)

    def reexec(self):
        """\
        重启?
        Relaunch the master and workers.
        """
        if self.pidfile is not None:
            self.pidfile.rename("%s.oldbin" % self.pidfile.fname)

        self.reexec_pid = os.fork()
        if self.reexec_pid != 0:
            self.master_name = "Old Master"
            return

        # 在新的进程中, 旧的进程如何处理呢?

        # 使用之前的环境变量重新创建一个环境
        environ = self.cfg.env_orig.copy()
        fds = [l.fileno() for l in self.LISTENERS]
        environ['GUNICORN_FD'] = ",".join([str(fd) for fd in fds])

        os.chdir(self.START_CTX['cwd'])
        self.cfg.pre_exec(self)

        # exec the process using the original environnement
        os.execvpe(self.START_CTX[0], self.START_CTX['args'], environ)

    def reload(self):
        """
        重新加载app, 并且spawn_worker, 最后再通过 manage_workers 杀掉多余的workers
        :return:
        """
        old_address = self.cfg.address

        # reset old environement
        for k in self.cfg.env:
            if k in self.cfg.env_orig:
                # reset the key to the value it had before
                # we launched gunicorn
                os.environ[k] = self.cfg.env_orig[k]
            else:
                # delete the value set by gunicorn
                try:
                    del os.environ[k]
                except KeyError:
                    pass

        # 1. 重新加载配置
        # reload conf
        self.app.reload()
        self.setup(self.app)

        # reopen log files
        self.log.reopen_files()

        # 2. 如果监听的地址改变，则需要重新创建sockets(一般情况下, 如: 代码升级，不会改变sockets)
        if old_address != self.cfg.address:
            #
            # 关闭已有的 listeners
            # close all listeners
            #
            [l.close() for l in self.LISTENERS]

            # 创建新的sockets, 这些listener如何工作呢?
            # init new listeners
            self.LISTENERS = create_sockets(self.cfg, self.log)

            self.log.info("Listening at: %s", ",".join(str(self.LISTENERS)))

        # do some actions on reload
        self.cfg.on_reload(self)

        # unlink pidfile
        if self.pidfile is not None:
            self.pidfile.unlink()

        # create new pidfile
        if self.cfg.pidfile is not None:
            self.pidfile = Pidfile(self.cfg.pidfile)
            self.pidfile.create(self.pid)

        # set new proc_name
        util._setproctitle("master [%s]" % self.proc_name)

        # 3. spawn new workers(这个地方是风险)

        self.log.info(Fore.GREEN + "Spawn New Workers: %d" + Fore.RESET, self.cfg.workers)

        # TODO: 太暴力
        #       不要一口气创建太多的新的进程
        for i in range(self.cfg.workers):
            self.spawn_worker()

        # 4. manage workers
        self.manage_workers()




    def murder_workers(self):
        """\
        Kill unused/idle workers
        """
        if not self.timeout:
            return

        # 1.0s执行一次

        # 如果有 timeout控制, 则检查时间timeout
        workers = list(self.WORKERS.items())
        for (pid, worker) in workers:
            diff = time.time() - worker.tmp.last_update()
            try:
                # 如果没有超时
                if diff < self.timeout_warning:
                    continue
                elif diff <= self.timeout:
                    if self.sentry_client:
                        # 如何获取worker的信息呢?
                        # 相同的URL只处理一次
                        url = worker.current_url.value
                        if url and self.pid_2_lasturl.get(pid) != url:
                            self.pid_2_lasturl[pid] = url
                            self.sentry_client.captureMessage('Gunicorn Worker WARNING timediff: %.3f, WARNGING THRESHOLD: %.3f, Processing URL: %s' % (diff, self.timeout_warning, worker.current_url.value))
                    continue
            except ValueError:
                continue
            if self.sentry_client:
                # 如何获取worker的信息呢?
                # 相同的URL只处理一次
                url = worker.current_url.value
                if url and self.pid_2_lasturl.get(pid) != url:
                    self.pid_2_lasturl[pid] = url
                    self.sentry_client.captureMessage('Gunicorn Worker timeout: %.3f, Max Allowed: %.3f, Processing URL: %s' % (diff, self.timeout, worker.current_url.value))

            # 这里的两种方式的区别?
            # signal.SIGTERM 是一种种比较温顺的方法(不过已经timeout, 说明这种方法失效了)
            if not worker.aborted:
                self.log.critical(Fore.RED + "WORKER TIMEOUT (pid:%s), Timeout: %s"+ Fore.RESET, pid, self.timeout)
                worker.aborted = True
                self.kill_worker(pid, signal.SIGABRT)
            else:
                # 强制杀死(表示通过 SIGABRT 没有杀死)
                self.kill_worker(pid, signal.SIGKILL)

    def reap_workers(self):
        """\
        Reap workers to avoid zombie processes
        """
        try:
            while True:
                wpid, status = os.waitpid(-1, os.WNOHANG)
                if not wpid:
                    break

                if self.reexec_pid == wpid:
                    self.reexec_pid = 0
                else:
                    # A worker said it cannot boot. We'll shutdown
                    # to avoid infinite start/stop cycles.
                    exitcode = status >> 8
                    if exitcode == self.WORKER_BOOT_ERROR:
                        reason = "Worker failed to boot."
                        raise HaltServer(reason, self.WORKER_BOOT_ERROR)
                    if exitcode == self.APP_LOAD_ERROR:
                        reason = "App failed to load."
                        raise HaltServer(reason, self.APP_LOAD_ERROR)

                    # 同步清理
                    worker = self.WORKERS.pop(wpid, None)
                    self.NEW_WORKERS.pop(wpid, None)

                    if not worker:
                        continue
                    worker.tmp.close()
        except OSError as e:
            if e.errno != errno.ECHILD:
                raise


    def manage_workers(self):
        """\
        Maintain the number of workers by spawning or killing
        as required.
        """

        # 不够则增加爱
        if len(self.WORKERS.keys()) < self.num_workers:
            self.spawn_workers()

        # 按照age升序排列
        workers = self.WORKERS.items()
        workers = sorted(workers, key=lambda w: w[1].age) # age是如何计算的？ age应该是出生的日期吧? 越新的worker的age越大

        # if self.sentry_client and len(workers) > self.num_workers:
        #     self.sentry_client.captureMessage('Gunicorn Kill Extra Workers IN manage_workers')

        # 在 self.NEW_WORKERS 没有起来时，不要轻易地杀掉旧的进程
        for pid, worker in self.NEW_WORKERS:
            if worker.booted.value:
                self.NEW_WORKERS.pop(pid)

        # 如果有效的进程过多，则删除部分旧的进程
        while len(workers) - len(self.NEW_WORKERS) > self.num_workers:
            (pid, _) = workers.pop(0)


            # self.log.info("Kill Worker: %s, %s, %s", pid, len(workers), self.num_workers)
            # self.log.info(get_stack_info())

            # 让多余的Process干完活了，就自己解决自己
            # KILL并不一定马上执行，因此 manage_workers 极可能在reload, 也可能在run中使用
            self.kill_worker(pid, signal.SIGTERM)

        self.log.debug("{0} workers".format(len(workers)), extra={"metric": "gunicorn.workers", "value": len(workers), "mtype": "gauge"})


    def spawn_worker(self):
        self.worker_age += 1

        # worker_class
        # 参考: gunicorn.workers.xxxx
        #
        worker = self.worker_class(self.worker_age, self.pid, self.LISTENERS, self.app, self.timeout / 2.0, self.cfg, self.log)
        self.cfg.pre_fork(self, worker)

        pid = os.fork()
        if pid != 0:
            # 主进程记住子进程的状态
            self.WORKERS[pid] = worker
            self.NEW_WORKERS[pid] = worker
            return pid

        # 子进程要做什么呢?
        # Process Child
        worker_pid = os.getpid()
        try:
            # 设置自己的状态
            util._setproctitle("worker [%s]" % self.proc_name)
            self.log.info("Booting worker with pid: %s", worker_pid)

            self.cfg.post_fork(self, worker)

            # 进程开始工作
            worker.init_process()


            sys.exit(0)
        except SystemExit:
            raise
        except AppImportError as e:
            self.log.debug("Exception while loading the application: \n%s", traceback.format_exc())
            print("%s" % e, file=sys.stderr)
            sys.stderr.flush()
            sys.exit(self.APP_LOAD_ERROR)
        except:
            self.log.exception("Exception in worker process:\n%s",
                    traceback.format_exc())
            if not worker.booted.value:
                sys.exit(self.WORKER_BOOT_ERROR)
            sys.exit(-1)
        finally:
            self.log.info("Worker exiting (pid: %s)", worker_pid)
            try:
                worker.tmp.close()
                self.cfg.worker_exit(self, worker)
            except:
                pass

    def spawn_workers(self):
        """\
        Spawn new workers as needed.

        This is where a worker process leaves the main loop
        of the master process.
        """

        for i in range(self.num_workers - len(self.WORKERS.keys())):
            self.spawn_worker()
            time.sleep(0.1 * random.random())

    def kill_workers(self, sig):
        """\
        Kill all workers with the signal `sig`
        :attr sig: `signal.SIG*` value
        """
        worker_pids = list(self.WORKERS.keys())
        for pid in worker_pids:
            self.kill_worker(pid, sig)

    def kill_worker(self, pid, sig):
        """\
        Kill a worker

        :attr pid: int, worker pid
        :attr sig: `signal.SIG*` value
         """
        self.NEW_WORKERS.pop(pid, None)

        try:
            os.kill(pid, sig)
        except OSError as e:
            if e.errno == errno.ESRCH:
                try:
                    worker = self.WORKERS.pop(pid)
                    worker.tmp.close()
                    self.cfg.worker_exit(self, worker)
                    return
                except (KeyError, OSError):
                    return
            raise
