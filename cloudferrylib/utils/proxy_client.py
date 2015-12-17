# Copyright (c) 2014 Mirantis Inc.
#
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and#
# limitations under the License.
import inspect
import time

from oslo_log import log

LOG = log.getLogger(__name__)

method_wrapper = type(object().__str__)

base_types = [inspect.types.BooleanType,
              inspect.types.BufferType,
              inspect.types.CodeType,
              inspect.types.ComplexType,
              inspect.types.DictProxyType,
              inspect.types.DictType,
              inspect.types.DictionaryType,
              inspect.types.EllipsisType,
              inspect.types.FileType,
              inspect.types.FloatType,
              inspect.types.FrameType,
              inspect.types.GeneratorType,
              inspect.types.GetSetDescriptorType,
              inspect.types.IntType,
              inspect.types.ListType,
              inspect.types.LongType,
              inspect.types.MemberDescriptorType,
              inspect.types.ModuleType,
              inspect.types.NoneType,
              inspect.types.NotImplementedType,
              inspect.types.SliceType,
              inspect.types.StringType,
              inspect.types.StringTypes,
              inspect.types.TracebackType,
              inspect.types.TupleType,
              inspect.types.TypeType,
              inspect.types.UnicodeType,
              inspect.types.XRangeType]


def is_wrapping(x):
    x = type(x)
    for t in base_types:
        if x is t:
            return False
    return True


class Proxy:
    def __init__(self, client, retry, wait_time):
        self.client = client
        self.retry = retry
        self.wait_time = wait_time

    def wait(self):
        time.sleep(self.wait_time)

    def __call__(self, *args, **kwargs):
        c = 0
        result = None
        is_retry = True
        while is_retry:
            try:
                result = self.client(*args, **kwargs)
                is_retry = False
            except Exception:  # pylint: disable=broad-except
                LOG.warning('Error happened while calling client',
                            exc_info=True)
                if c < self.retry:
                    c += 1
                    self.wait()
                else:
                    raise
        return result

    def __getattr__(self, name):
        attr = getattr(self.client, name)
        if inspect.ismethod(attr) or \
                (type(attr) is method_wrapper) or \
                is_wrapping(attr):
            return Proxy(attr, self.retry, self.wait_time)
        return attr
