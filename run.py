#!/usr/bin/env python3
"""
run.py
======
Development entry point. Binds to 127.0.0.1 ONLY, satisfying the assignment's
authorised-lab restriction that all testing occurs on localhost.
"""
from werkzeug.serving import WSGIRequestHandler

from secure_app import create_app

# The development server writes its own Server: header at the HTTP layer,
# below the WSGI application, so an after_request hook cannot remove it. It is
# suppressed here as well; in a deployed configuration the same result is
# obtained with 'server_tokens off' in the reverse proxy.
WSGIRequestHandler.server_version = "registration-app"
WSGIRequestHandler.sys_version = ""

app = create_app()

if __name__ == "__main__":
    # host is pinned to loopback; it is not configurable from the environment.
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])
