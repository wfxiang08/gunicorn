# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import os
import sys

from gunicorn.errors import ConfigError
from gunicorn.app.base import Application
from gunicorn import util


class WSGIApplication(Application):
    def init(self, parser, opts, args):

        # pasteapp的处理
        if opts.paste and opts.paste is not None:
            app_name = 'main'
            path = opts.paste
            if '#' in path:
                path, app_name = path.split('#')
            path = os.path.abspath(os.path.normpath(
                os.path.join(util.getcwd(), path)))

            if not os.path.exists(path):
                raise ConfigError("%r not found" % path)

            # paste application, load the config
            self.cfgurl = 'config:%s#%s' % (path, app_name)
            self.relpath = os.path.dirname(path)

            from .pasterapp import paste_config
            return paste_config(self.cfg, self.cfgurl, self.relpath)

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

        # add the path to sys.path
        sys.path.insert(0, self.cfg.chdir)

    def load_wsgiapp(self):
        """
            加载 wsgiapp
            :return:
        """
        self.chdir()

        # load the app
        return util.import_app(self.app_uri)

    def load_pasteapp(self):
        self.chdir()

        # load the paste app
        from .pasterapp import load_pasteapp
        return load_pasteapp(self.cfgurl, self.relpath, global_conf=None)

    def load(self):
        """
            加载app， 返回app对象
            :return:
        """
        if self.cfg.paste is not None:
            return self.load_pasteapp()
        else:
            return self.load_wsgiapp()


def run():
    """\
    The ``gunicorn`` command line runner for launching Gunicorn with
    generic WSGI applications.
    """
    from gunicorn.app.wsgiapp import WSGIApplication
    #
    # 如何解析参数呢?
    # gunicorn --workers=2 test:app
    #
    WSGIApplication("%(prog)s [OPTIONS] [APP_MODULE]").run()


if __name__ == '__main__':
    run()
