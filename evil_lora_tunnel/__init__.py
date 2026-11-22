"""Receive-only LoRa recording for RaspyJack, adapted from LORA-Pager-Pipe."""


class RadioError(RuntimeError):
    """A receive backend could not initialize, tune or read a packet."""
