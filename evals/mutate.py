"""The evidence checker's regression set. Same as `asa eval checker`; run from the repo folder: python evals/mutate.py

The mutants and the clean set live in src/asa/mutate.py so the installed `asa` command can run them.
"""
from asa.mutate import main

if __name__ == "__main__":
    raise SystemExit(main())
