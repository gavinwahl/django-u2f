try:
    from u2flib_server import u2f_v2 as u2f
    U2F_ENABLED = True
except ImportError:
    U2F_ENABLED = False
    u2f = None
