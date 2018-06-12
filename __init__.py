
try:
    from passpacker import PassPacker, passwords
except (Exception, ) as e:
    from .passpacker import PassPacker, passwords
