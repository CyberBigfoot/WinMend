"""UI-independent prompt ports used by maintenance handlers.

The Qt dialog adapter binds these ports when it loads. Maintenance modules
can therefore be imported and tested without importing Qt.
"""


class PromptPort:
    def __init__(self):
        self._adapter = None

    def bind(self, adapter):
        self._adapter = adapter

    def __getattr__(self, name):
        if self._adapter is None:
            raise RuntimeError("The application has not bound its dialog adapter.")
        return getattr(self._adapter, name)


messagebox = PromptPort()
simpledialog = PromptPort()


def bind_prompts(message_adapter, input_adapter):
    messagebox.bind(message_adapter)
    simpledialog.bind(input_adapter)
