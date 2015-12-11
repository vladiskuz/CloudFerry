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


from fabric.api import env
from fabric.api import settings

from cloudferrylib.os.actions import utils as action_utils

from cloudferrylib.utils import cmd_cfg
from cloudferrylib.utils import driver_transporter
from cloudferrylib.utils import rbd_util
from cloudferrylib.utils import utils


LOG = utils.get_log(__name__)


class SSHFileToCeph(driver_transporter.DriverTransporter):
    def transfer(self, data):
        ssh_ip_src = self.src_cloud.getIpSsh()
        ssh_ip_dst = self.dst_cloud.getIpSsh()
        action_utils.delete_file_from_rbd(ssh_ip_dst, data['path_dst'])
        with (settings(host_string=ssh_ip_src,
                       connection_attempts=env.connection_attempts),
              utils.ForwardAgent(env.key_filename)):
            rbd_import = rbd_util.RbdUtil.rbd_import_cmd
            ssh_cmd_dst = cmd_cfg.ssh_cmd
            ssh_dst = ssh_cmd_dst(ssh_ip_dst, rbd_import)

            dd = cmd_cfg.dd_cmd_if
            ssh_cmd_src = cmd_cfg.ssh_cmd
            ssh_src = ssh_cmd_src(data['host_src'], dd)

            process = ssh_src >> ssh_dst
            process = process('1M', data['path_src'], '2', '-',
                              data['path_dst'])

            self.src_cloud.ssh_util.execute(process)
