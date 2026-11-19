"""Allow ``python -m fhir_dissector``."""
import sys

from fhir_dissector.cli import main

if __name__ == "__main__":
    sys.exit(main())
