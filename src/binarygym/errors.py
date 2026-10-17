"""Exception types shared across BinaryGym."""


class BinaryGymError(Exception):
    """Base class for all expected, user-reportable errors."""


class SpecError(BinaryGymError):
    """A challenge specification (or private record) is malformed."""


class CompileError(BinaryGymError):
    """The native compiler rejected generated source or is unavailable."""


class ValidationFailed(BinaryGymError):
    """A generated challenge did not pass validation and must not be published."""


class ChallengeNotFound(BinaryGymError):
    """A challenge or its private record could not be located."""
