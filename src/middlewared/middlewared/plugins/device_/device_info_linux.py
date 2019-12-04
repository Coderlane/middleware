import blkid

from .device_info_base import DeviceInfoBase
from middlewared.service import Service


class DeviceService(Service, DeviceInfoBase):

    async def get_serial(self):
        raise NotImplementedError()

    def get_disk(self):
        disks = {}
        for block_device in filter(
            lambda b: b.name not in ('sr0',),
            blkid.list_block_devices()
        ):
            disks[block_device.name] = {
                k: v for k, v in block_device.__getstate__().items()
                if k not in ('partitions_data', 'io_limits')
            }
        return disks