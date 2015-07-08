# -*- coding: utf-8 -

from __future__ import absolute_import
import os
import sys

from gunicorn_zmq.app.base import Application
from gunicorn_zmq import util


class ZmqApplication(Application):
    def init(self, parser, opts, args):
        if len(args) < 1:
            parser.error("No application module specified.")

        self.cfg.set("default_proc_name", args[0])
        self.app_uri = args[0] # 例如: test:app


    def chdir(self):
        """
            切换到指定的dir, 并且修改 sys.path
            :return:
        """
        # chdir to the configured path before loading,
        # default is the current dir
        os.chdir(self.cfg.chdir)

        # 调整Python的搜索路径
        sys.path.insert(0, self.cfg.chdir)

    def load(self):
        """
            加载app， 返回app对象
        """
        self.chdir()

        return util.import_app(self.app_uri)


def run():
    """\
    The ``gunicorn_zmq`` command line runner for launching gunicorn_zmq with
    generic WSGI applications.
    """
    from gunicorn_zmq.app.zmqapp import ZmqApplication

    #
    # 如何解析参数呢?
    # gunicorn_zmq --workers=2 test:app
    #
    ZmqApplication("%(prog)s [OPTIONS] [APP_MODULE]").run()


if __name__ == '__main__':
    run()
