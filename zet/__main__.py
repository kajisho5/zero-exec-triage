"""Started with python3 -I zet/__main__.py (-I does not put the script's directory on sys.path, so the repository
root is added explicitly. Only ZET's own location is added)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from zet.cli import main  # noqa: E402

sys.exit(main())
