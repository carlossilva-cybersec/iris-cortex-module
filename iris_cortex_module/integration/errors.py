class CortexModuleError(Exception):
    """Error returned to the client as ``{"status": "error", "message": ...}``."""

    def __init__(self, message: str, status_code: int = 400, data=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.data = data
