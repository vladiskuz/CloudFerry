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

from cloudferrylib.utils import cmd_cfg
from cloudferrylib.utils import driver_transporter
from cloudferrylib.utils import rbd_util
from cloudferrylib.utils import utils


LOG = utils.get_log(__name__)


class SSHCephToFile(driver_transporter.DriverTransporter):
    def transfer(self, data):
        ssh_ip_src = self.src_cloud.getIpSsh()
        ssh_ip_dst = self.dst_cloud.getIpSsh()
        with utils.ForwardAgent(env.key_filename), utils.up_ssh_tunnel(
                data['host_dst'], ssh_ip_dst, ssh_ip_src) as port:
            dd = cmd_cfg.dd_cmd_of
            ssh_cmd = cmd_cfg.ssh_cmd_port
            rbd_export = rbd_util.RbdUtil.rbd_export_cmd

            ssh_dd = ssh_cmd(port, 'localhost', dd)

            process = rbd_export >> ssh_dd
            process = process(data['path_src'], '-', '1M',
                              data['path_dst'])

            self.src_cloud.ssh_util.execute(process)
