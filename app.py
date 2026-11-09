import os
from pixshare import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    # Le mode debug de Flask donne un shell Python à quiconque atteint le serveur :
    # on ne l'active que si on le demande explicitement (FLASK_DEBUG=1) et on
    # n'écoute alors que sur la machine locale.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = "127.0.0.1" if debug else "0.0.0.0"
    app.run(host=host, port=port, debug=debug)
