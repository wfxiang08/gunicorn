# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import sys

# supported gunicorn workers.
SUPPORTED_WORKERS = {
    "sync": "gunicorn.workers.sync.SyncWorker",
    "gevent": "gunicorn.workers.ggevent.GeventWorker",
    "gevent_wsgi": "gunicorn.workers.ggevent.GeventPyWSGIWorker",
    "gevent_pywsgi": "gunicorn.workers.ggevent.GeventPyWSGIWorker",
}

