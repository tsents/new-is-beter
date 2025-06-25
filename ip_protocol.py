

def pretty_ip(raw_ip : bytes) -> str:
    """
    Formats ip bytes from raw format, to *.*.*.* string
    """
    return ".".join([str(i) for i in raw_ip])
