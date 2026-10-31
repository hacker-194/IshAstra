import sys

sys.path.insert(0, "src")
with open("/tmp/conftest_was_loaded", "w") as f:
    print("CONFTEST_LOADING_MARKER", file=f)
print("conftest loaded at import time")
