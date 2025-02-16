# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2024  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
#    This program is distributed in the hope that it will be useful,         #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#    GNU General Public License for more details.                            #
#                                                                            #
#    You should have received a copy of the GNU General Public License       #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                            #
# ========================================================================== #

import asyncio
import functools

from typing import Callable
from typing import Any

from ...logging import get_logger

from ... import tools
from ... import aiotools
from ... import aioproc

from ...yamlconf import Option

from ...validators.basic import valid_float_f01
from ...validators.basic import valid_stripped_string_not_empty
from ...validators.net import valid_ip_or_host
from ...validators.net import valid_port
from ...validators.os import valid_command

from . import GpioDriverOfflineError
from . import BaseUserGpioDriver


# =====
_OUTPUTS = {
    True: "1",
    False: "2",
    "cycle": "3",
}

_INPUTS = {
    "1": True,
    "2": False,
}


# =====
class Plugin(BaseUserGpioDriver):  # pylint: disable=too-many-instance-attributes
    def __init__(  # pylint: disable=super-init-not-called
        self,
        instance_name: str,
        notifier: aiotools.AioNotifier,

        host: str,
        port: str,
        oid_outlets: str,
        status_cmd: list[str],
        set_cmd: list[str],

        state_poll: float,
        switch_delay: float,
    ) -> None:

        super().__init__(instance_name, notifier)

        self.__host = host
        self.__port = port
        self.__status_cmd = status_cmd
        self.__set_cmd = set_cmd
        self.__oid_outlets = oid_outlets

        self.__state_poll = state_poll
        self.__switch_delay = switch_delay

        self.__state: dict[str, (bool | None)] = {}

    @classmethod
    def get_plugin_options(cls) -> dict:
        return {
            "host":   Option("",  type=valid_ip_or_host),
            "port":   Option("161", type=valid_port),
            "oid_outlets": Option("SNMPv2-SMI::enterprises.3808.1.1.3.3.3.1.1"),

            "status_cmd": Option([
                "/usr/bin/snmpwalk",
                "-v", "1", "-c", 
                "private", "{host}",
                "{oid_outlets}.4.{pin}",
            ], type=valid_command),
            "set_cmd": Option([
                "/usr/bin/snmpset",
                "-v", "1", "-c", 
                "private", "{host}",
                "{oid_outlets}.4.{pin}",
                "i", "{action}"
            ], type=valid_command),

            "state_poll": Option(5.0, type=valid_float_f01),
            "switch_delay": Option(1.0,  type=valid_float_f01),
        }

    @classmethod
    def get_pin_validator(cls) -> Callable[[Any], Any]:
        return valid_stripped_string_not_empty

    def register_input(self, pin: str, debounce: float) -> None:
        _ = debounce
        self.__state[pin] = None

    def register_output(self, pin: str, initial: (bool | None)) -> None:
        self.__state[pin] = initial

    def prepare(self) -> None:
        get_logger(0).info("Probing driver %s on %s:%d ...", self, self.__host, self.__port)

    async def run(self) -> None:
        prev_state: (dict | None) = None
        while True:
            for pin in self.__state:
                await self.__update_power(pin)

            if self.__state != prev_state:
                get_logger(0).info("State changed: %s", self.__state)
                self._notifier.notify()
                prev_state = self.__state
            await self._notifier.wait(self.__state_poll)

    async def read(self, pin: str) -> bool:
        if self.__state[pin] is None:
            raise GpioDriverOfflineError(self)
        return self.__state[pin]  # type: ignore

    async def write(self, pin: str, state: bool) -> None:
        try:
            await self.__set_power(state, pin)
        except Exception as ex:
            raise GpioDriverOfflineError(self)
        await asyncio.sleep(self.__switch_delay)
        self._notifier.notify()

    # =====

    async def __update_power(self, pin) -> None:
        try:
            (proc, text) = await aioproc.read_process(**self.__make_snmpwalk_kwargs(pin))
            if proc.returncode != 0:
                raise RuntimeError(f"SNMP error: retcode={proc.returncode}")
            stripped = text.strip()
            if stripped.startswith(f"{self.__oid_outlets}.4.{pin} = INTEGER: "):
                self.__state[pin] = _INPUTS[stripped[-1]]
                return
            raise RuntimeError(f"Invalid smnpwalk response: {text}")
        except Exception as ex:
            get_logger(0).error("Can't fetch SNMP power status from %s:%d: %s",
                                self.__host, self.__port, tools.efmt(ex))
            self.__state = dict.fromkeys(self.__state, None)

    async def __set_power(self, state, pin) -> None:
        try:
            (proc, text) = await aioproc.read_process(**self.__make_snmpset_kwargs(state, pin))
            if proc.returncode != 0:
                raise RuntimeError(f"SNMP error: retcode={proc.returncode}")
            stripped = text.strip()
            if stripped.startswith(f"{self.__oid_outlets}.4.{pin} = INTEGER: "):
                self.__state[pin] = _INPUTS[stripped[-1]]
                return
            raise RuntimeError(f"Invalid smnpset response: {text}")
        except Exception as ex:
            get_logger(0).error("Can't set SNMP power status from %s:%d: %s",
                                self.__host, self.__port, tools.efmt(ex))
            self.__state = dict.fromkeys(self.__state, None)

    @functools.lru_cache()
    def __make_snmpwalk_kwargs(self, pin: str) -> dict:
        return {
            "cmd": [
                part.format(
                    host=self.__host,
                    oid_outlets=self.__oid_outlets,
                    pin=pin,
                )
                for part in self.__status_cmd
            ]
        }

    @functools.lru_cache()
    def __make_snmpset_kwargs(self, action: str, pin: str) -> dict:
        return {
            "cmd": [
                part.format(
                    host=self.__host,
                    oid_outlets=self.__oid_outlets,
                    pin=pin,
                    action=_OUTPUTS[action],
                )
                for part in self.__set_cmd
            ]
        }

    def __str__(self) -> str:
        return f"CyberPower({self._instance_name})"

    __repr__ = __str__
