##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2023 Ruedi Steinmann <ruediste@gmail.com>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd
from math import ceil

RX = 0
TX = 1
rxtx_channels = ("RX", "TX")

commandTable = {
    0x02: {
        "Name": "FLASH_BEGIN",
        "Description": "Begin Flash Download",
        "Input": "Four 32-bit words: size to erase, number of data packets, data size in one packet, flash offset. A fifth 32-bit word passed to ROM loader only: 1 to begin encrypted flash, 0 to not.",
    },
    0x03: {
        "Name": "FLASH_DATA",
        "Description": "Flash Download Data",
        "Input": "Four 32-bit words: data size, sequence number, 0, 0, then data. Uses Checksum.",
    },
    0x04: {
        "Name": "FLASH_END",
        "Description": "Finish Flash Download",
        "Input": "One 32-bit word: 0 to reboot, 1 to run user code. Not necessary to send this command if you wish to stay in the loader",
    },
    0x05: {
        "Name": "MEM_BEGIN",
        "Description": "Begin RAM Download Start",
        "Input": "Total size, number of data packets, data size in one packet, memory offset",
    },
    0x06: {
        "Name": "MEM_END",
        "Description": "Finish RAM Download",
        "Input": "Two 32-bit words: execute flag, entry point address",
    },
    0x07: {
        "Name": "MEM_DATA",
        "Description": "RAM Download Data",
        "Input": "Four 32-bit words: data size, sequence number, 0, 0, then data. Uses Checksum.",
    },
    0x08: {
        "Name": "SYNC",
        "Description": "Sync Frame",
        "Input": "36 bytes: 0x07 0x07 0x12 0x20, followed by 32 x 0x55",
    },
    0x09: {
        "Name": "WRITE_REG",
        "Description": "Write 32-bit memory address",
        "Input": "Four 32-bit words: address, value, mask and delay (in microseconds)",
    },
    0x0A: {
        "Name": "READ_REG",
        "Description": "Read 32-bit memory address",
        "Input": "Address as 32-bit word\n\nRead data as 32-bit word in value field.",
    },
    0x0B: {
        "Name": "SPI_SET_PARAMS",
        "Description": "Configure SPI flash",
        "Input": "Six 32-bit words: id, total size in bytes, block size, sector size, page size, status mask.",
    },
    0x0D: {
        "Name": "SPI_ATTACH",
        "Description": "Attach SPI flash",
        "Input": "32-bit word: Zero for normal SPI flash. A second 32-bit word (should be 0) is passed to ROM loader only.",
    },
    0x0F: {
        "Name": "CHANGE_BAUDRATE",
        "Description": "Change Baud rate",
        "Input": "Two 32-bit words: new baud rate, 0 if we are talking to the ROM loader or the current/old baud rate if we are talking to the stub loader.",
    },
    0x10: {
        "Name": "FLASH_DEFL_BEGIN",
        "Description": "Begin compressed flash download",
        "Input": "Four 32-bit words: uncompressed size, number of data packets, data packet size, flash offset. With stub loader the uncompressed size is exact byte count to be written, whereas on ROM bootloader it is rounded up to flash erase block size. A fifth 32-bit word passed to ROM loader only: 1 to begin encrypted flash, 0 to not.",
    },
    0x11: {
        "Name": "FLASH_DEFL_DATA",
        "Description": "Compressed flash download data",
        "Input": "Four 32-bit words: data size, sequence number, 0, 0, then data. Uses Checksum.\n\nError code 0xC1 on checksum error.",
    },
    0x12: {
        "Name": "FLASH_DEFL_END",
        "Description": "End compressed flash download",
        "Input": "One 32-bit word: 0 to reboot, 1 to run user code. Not necessary to send this command if you wish to stay in the loader.",
    },
    0x13: {
        "Name": "SPI_FLASH_MD5",
        "Description": "Calculate MD5 of flash region",
        "Input": "Four 32-bit words: address, size, 0, 0\n\nBody contains 16 raw bytes of MD5 followed by 2 status bytes (stub loader) or 32 hex-coded ASCII (ROM loader) of calculated MD5",
    },
    0x14: {
        "Name": "GET_SECURITY_INFO",
        "Description": "Read chip security info",
        "Input": "32 bits flags, 1 byte flash_crypt_cnt, 7x1 byte key_purposes, 32-bit word chip_id, 32-bit word eco_version",
    },
    0xD0: {
        "Name": "ERASE_FLASH (stub loader))",
        "Description": "Erase entire flash chip",
        "Input": "",
        "Output": "",
    },
    0xD1: {
        "Name": "ERASE_REGION (stub loader)",
        "Description": "Erase flash region",
        "Input": "Two 32-bit words: flash offset to erase, erase size in bytes. Both must be multiples of flash sector size.",
        "Output": "",
    },
    0xD2: {
        "Name": "READ_FLASH (stub loader)",
        "Description": "Read flash",
        "Input": "Four 32-bit words: flash offset, read length, flash sector size, read packet size, maximum number of un-acked packets",
        "Output": "",
    },
    0xD3: {
        "Name": "RUN_USER_CODE (stub loader)",
        "Description": "Exits loader and runs user code",
        "Input": "",
        "Output": "",
    },
}


class No_more_data(Exception):
    """This exception is a signal that we should stop parsing an ADU as there
    is no more data to parse."""

    pass


class SlipDecoder:
    """Decoder for the SLIP protocol, used to encapsulate the messages"""

    def __init__(self):
        self.slipStatus = "idle"
        self.slipEscStart = 0

    def decode(self, ss, es, value):
        if self.slipStatus == "idle":
            if value == 0xC0:
                self.onFrameStart(ss, es)
                self.slipStatus = "in_frame"
            else:
                self.onError(ss, es, "Unexpected value: 0x%02x" % value)
        elif self.slipStatus == "in_frame":
            if value == 0xC0:
                self.onFrameEnd(ss, es)
                self.slipStatus = "idle"
            elif value == 0xDB:
                self.slipStatus = "escape"
                self.slipEscStart = ss
            else:
                self.onData(ss, es, value)
        elif self.slipStatus == "escape":
            if value == 0xDC:
                self.onData(self.slipEscStart, es, 0xC0)
            elif value == 0xDD:
                self.onData(self.slipEscStart, es, 0xDB)
            else:
                self.onError(
                    self.slipEscStart, es, "Unexpected escape value: 0x%02x" % value
                )
            self.slipStatus = "in_frame"

    def onData(self, ss, es, value):
        pass

    def onFrameStart(self, ss, es):
        pass

    def onFrameEnd(self, ss, es):
        pass

    def onError(self, ss, es, message):
        pass


class BootloaderProtocolDecoder(SlipDecoder):
    """Decoder for the bootloader protocol"""

    def __init__(self, decoder, direction):
        super().__init__()
        self.decoder = decoder
        self.direction = direction
        self.status = "cmd"
        self.lastStatus = ""
        pass

    def onData(self, ss, es, value):
        if self.status != self.lastStatus:
            self.segmentStart = ss
            self.count = 0
            self.acc = 0
            self.lastStatus = self.status
        else:
            self.count = self.count + 1

        if self.status == "dir":
            self.status = "cmd"
            if value == 0x00:
                str = "REQ"
            elif value == 0x01:
                str = "RES"
            else:
                self.decoder.puta(
                    ss,
                    es,
                    self.direction + "-error",
                    "Invalid direction: 0x%02x" % value,
                )
                return
            self.decoder.puta(ss, es, self.direction + "-dir", ["DIR: " + str, str])
        elif self.status == "cmd":
            self.status = "size"
            if value in commandTable:
                cmd = commandTable[value]
                self.lastCmd = cmd
                self.decoder.puta(
                    ss,
                    es,
                    self.direction + "-cmd",
                    [
                        "CMD: " + cmd["Name"],
                        cmd["Name"],
                    ],
                )
            else:
                self.decoder.puta(
                    ss,
                    es,
                    self.direction + "-error",
                    "Invalid command: 0x%02x" % value,
                )
        elif self.status == "size":
            self.acc = self.acc + (value << (8 * self.count))
            if self.count == 1:
                self.status = "checksum"
                self.decoder.puta(
                    self.segmentStart,
                    es,
                    self.direction + "-size",
                    ["Size: 0x%04x" % self.acc, "0x%04x" % self.acc],
                )
        elif self.status == "checksum":
            self.acc = self.acc + (value << (8 * self.count))
            if self.count == 3:
                self.status = "data"
                if self.direction == "pm":
                    self.decoder.puta(
                        self.segmentStart,
                        es,
                        self.direction + "-checksum",
                        ["Checksum: 0x%08x" % self.acc, "0x%08x" % self.acc],
                    )
                else:
                    self.decoder.puta(
                        self.segmentStart,
                        es,
                        self.direction + "-value",
                        ["Value: 0x%08x" % self.acc, "0x%08x" % self.acc],
                    )

    def onFrameStart(self, ss, es):
        self.status = "dir"
        self.lastStatus = ""
        self.lastCmd = None
        pass

    def onFrameEnd(self, ss, es):
        if self.status == "data":
            if self.lastCmd != None:
                self.decoder.puta(
                    self.segmentStart,
                    ss,
                    self.direction + "-data",
                    ["Data: " + self.lastCmd["Input"], "Data"],
                )
            else:
                self.decoder.puta(
                    self.segmentStart, ss, self.direction + "-data", "Data"
                )
        pass

    def onError(self, ss, es, message):
        pass


class Decoder(srd.Decoder):
    api_version = 3
    id = "esp32-programmer"
    name = "Esp32-Prog"
    longname = "ESP32 Programmer"
    desc = "Decodes the protocol of the ESP32 programmer/bootloader"
    license = "gplv3+"
    inputs = ["uart"]
    outputs = []
    tags = ["Embedded/industrial"]
    annotations = (
        ("pm-dir", "PM Direction"),
        ("pm-cmd", "PM Command"),
        ("pm-size", "PM Size"),
        ("pm-checksum", "PM Checksum"),
        ("pm-data", "PM Data"),
        ("pm-error", "PM Error"),
        ("mp-dir", "MP Direction"),
        ("mp-cmd", "MP Command"),
        ("mp-size", "MP Size"),
        ("mp-value", "MP Value"),
        ("mp-data", "MP Data"),
        ("mp-error", "MP Error"),
    )
    annotation_rows = (
        (
            "pm",
            "Programmer->module",
            (
                0,
                1,
                2,
                3,
                4,
                5,
            ),
        ),
        (
            "mp",
            "Module->programmer",
            (
                6,
                7,
                8,
                9,
                10,
                11,
            ),
        ),
    )
    options = (
        {
            "id": "pm_channel",
            "desc": "Programmer -> module channel",
            "default": rxtx_channels[0],
            "values": rxtx_channels,
        },
        {
            "id": "mp_channel",
            "desc": "Module -> programmer channel",
            "default": rxtx_channels[1],
            "values": rxtx_channels,
        },
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.pmDecoder = BootloaderProtocolDecoder(self, "pm")
        self.mpDecoder = BootloaderProtocolDecoder(self, "mp")

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def puta(self, start, end, ann_str, message):
        """Put an annotation from start to end, with ann as a
        string. This means you don't have to know the ann's
        number to write annotations to it."""
        ann = [s[0] for s in self.annotations].index(ann_str)

        if not isinstance(message, list):
            message = [message]
        self.put(start, end, self.out_ann, [ann, message])

    def decode(self, ss, es, data):
        ptype, rxtx, pdata = data

        if ptype != "FRAME":
            return

        value, is_valid = pdata

        # Decide what ADU(s) we need this packet to go to.
        # Note that it's possible to go to both ADUs.
        if rxtx_channels[rxtx] == self.options["pm_channel"]:
            self.pmDecoder.decode(ss, es, value)
        if rxtx_channels[rxtx] == self.options["mp_channel"]:
            self.mpDecoder.decode(ss, es, value)
