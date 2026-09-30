class SwitchError(RuntimeError):
    """Base class for errors reported by the switch or this library."""


class LoginError(SwitchError):
    """Authentication with the switch failed."""


class ModelDetectionError(SwitchError):
    """The switch model could not be determined; pass model=... explicitly."""


class UnsupportedFeatureError(SwitchError):
    """The operation isn't available on this model (e.g. PoE on a GS308E)."""
