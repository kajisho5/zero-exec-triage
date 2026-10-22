"""python3 -I zet/__main__.py で起動する（-I はスクリプトのディレクトリを sys.path に入れないため、
リポジトリのルートを明示的に追加する。追加するのは ZET 自身の場所だけ）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from zet.cli import main  # noqa: E402

sys.exit(main())
