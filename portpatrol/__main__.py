"""Allow `python -m portpatrol`."""

import sys

from portpatrol.cli import main

if __name__ == "__main__":
    sys.exit(main())
