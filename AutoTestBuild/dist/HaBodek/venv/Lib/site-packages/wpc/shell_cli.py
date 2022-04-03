# -*- coding: utf-8 -*-

from wpc.boot import boot
from wpc.cli import shell

if __name__ == "__main__":
    boot.bootstrap()
    shell.cli_commands()

    # sys.exit(main())  # pragma: no cover

