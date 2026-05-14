def unsafe_open(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()
