from peat import utils
from peat.protocols import SSH


class IdirectSSH(SSH):
    PRE_WRITE_SLEEP: float = 0.0
    POST_WRITE_SLEEP: float = 0.0

    # TODO: set key algorithm and SSL version?

    def read(
        self,
        delay: float | None = None,
        strip_whitespace: bool = True,
        wait_until_ready: bool = True,
    ) -> str:
        data = super().read(delay, strip_whitespace, wait_until_ready)

        # Exclude the command from the returned data
        if data and data.count("\n") >= 1:
            data = data.partition("\n")[2]

        # Remove trailing prompt characters, "# "
        if data:
            data = data.rstrip().rstrip("#").rstrip()

        return data

    def disconnect(self) -> None:
        if self.connected and self._comm:
            self.log.debug(f"Disconnected from Idirect at {utils.time_now()}")
            try:
                self.write("exit")
            except Exception:
                pass
        super().disconnect()
