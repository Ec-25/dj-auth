from os import getenv


def getenv_or_error(varname: str) -> str:
    """Get an environment variable, or raise an error if it is not set."""
    vardata = getenv(varname)
    if vardata is None:
        raise EnvironmentError(f"Environment variable {varname} is not set")
    return vardata
