"""Inject DracoLure into an existing Flask app in one line.

    pip install ../python-sdk
    DRACOLURE_URL=http://localhost:5000 python flask_app.py

Every request this app receives is reported to DracoLure and classified.
Switch mode="block" to have the middleware return 403 for quarantined sources.
"""

import os

from flask import Flask

from dracolure import DracoLureClient, DracoLureMiddleware

app = Flask(__name__)

client = DracoLureClient(
    base_url=os.environ.get("DRACOLURE_URL", "http://localhost:5000"),
    api_key=os.environ.get("DRACOLURE_API_KEY"),
)

# The one line that "injects" DracoLure. monitor = async, zero-latency.
app.wsgi_app = DracoLureMiddleware(app.wsgi_app, client, mode="monitor")


@app.route("/")
def home():
    return "Protected app — every probe is reported to DracoLure."


if __name__ == "__main__":
    app.run(port=8090)
