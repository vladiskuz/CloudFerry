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

from email.mime import multipart
from email.mime import text
import multiprocessing
import os
import random
import smtplib
import string
import time
import timeit

from fabric.api import env
from fabric.api import local
from fabric.api import run
from fabric.api import settings
from fabric.api import sudo
from fabric.context_managers import hide
import ipaddr
import yaml


ANY = "any"
AVAILABLE = 'available'

BOOT_FROM_IMAGE = "boot_image"
BOOT_FROM_VOLUME = "boot_volume"

CEPH = "ceph"
COMPUTE_RESOURCE = 'compute'
CONTAINERS = 'containers'

DIFF_BODY = 'diff'
DISK = "disk"
DISK_EPHEM = "disk.local"

EPHEMERAL = "ephemeral"
EPHEMERAL_BODY = 'ephemeral'

HOST_DST = 'host_dst'
HOST_SRC = 'host_src'

IDENTITY_RESOURCE = 'identity'
IGNORE = 'ignore'
IMAGE_BODY = 'image'
IMAGE_RESOURCE = 'image'
IMAGES_TYPE = 'images'
IN_USE = 'in-use'
INSTANCE_BODY = 'instance'
INSTANCES_TYPE = 'instances'
INTERFACES = 'interfaces'
ISCSI = "iscsi"

LEN_UUID_INSTANCE = 36

META_INFO = 'meta'

NETWORK_RESOURCE = 'network'
NO = "no"

OBJSTORAGE_RESOURCE = 'objstorage'
OLD_ID = 'old_id'

PATH_DST = 'path_dst'
PATH_SRC = 'path_src'

QCOW2 = "qcow2"

RAW = "raw"

SSH_CMD = \
    "ssh -oStrictHostKeyChecking=no -L %s:%s:22 -R %s:localhost:%s %s -Nf"
STATUS = 'status'
STORAGE_RESOURCE = 'storage'

TENANTS_TYPE = 'tenants'

VOLUMES_TYPE = 'volumes'
VOLUME_BODY = 'volume'
VOLUMES_DB = 'volumes_db'

YES = "yes"


up_ssh_tunnel = None


class ExtDict(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError("Exporter has no attribute %s" % name)


primitive = [int, long, bool, float, type(None), str, unicode]


class GeneratorPassword(object):
    def __init__(self, length=7):
        self.length = length
        self.chars = string.ascii_letters + string.digits + '@#$%&*'

    def get_random_password(self):
        return self.__generate_password()

    def __generate_password(self):
        return ''.join(random.choice(self.chars) for i in range(self.length))


class Postman(object):
    def __init__(self, username, password, from_addr, mail_server):
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.mail_server = mail_server

    def __enter__(self):
        self.server = smtplib.SMTP(self.mail_server)
        self.server.ehlo()
        self.server.starttls()
        self.server.login(self.username, self.password)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server.quit()

    def send(self, to, subject, msg):
        msg_mime = multipart.MIMEMultipart('alternative')
        msg_mime.attach(text.MIMEText(msg, 'html'))
        msg_mime['Subject'] = subject
        msg_mime['From'] = self.from_addr
        msg_mime['To'] = to
        self.server.sendmail(self.from_addr, to, msg_mime.as_string())

    def close(self):
        self.server.quit()


class Templater(object):
    def render(self, name_file, args):
        temp_file = open(name_file, 'r')
        temp_render = temp_file.read()
        for arg in args:
            temp_render = temp_render.replace("{{%s}}" % arg, args[arg])
        temp_file.close()
        return temp_render


class ForwardAgent(object):
    """Forwarding ssh-key for access on to source and
       destination clouds via ssh.
    """

    def __init__(self, key_files):
        self.key_files = key_files

    def _agent_already_running(self):
        with settings(hide('warnings', 'running', 'stdout', 'stderr'),
                      warn_only=True,
                      connection_attempts=env.connection_attempts):
            res = local("ssh-add -l", capture=True)

            if res.succeeded:
                present_keys = res.split(os.linesep)
                # TODO: this will break for path with whitespaces
                present_keys_paths = [
                    present_key.split(' ')[2] for present_key in present_keys
                    ]
                for key in self.key_files:
                    if os.path.expanduser(key) not in present_keys_paths:
                        return False
                return True

        return False

    def __enter__(self):
        if self._agent_already_running():
            return
        key_string = ' '.join(self.key_files)
        start_ssh_agent = ("eval `ssh-agent` && echo $SSH_AUTH_SOCK && "
                           "ssh-add %s") % key_string
        info_agent = local(start_ssh_agent, capture=True).split("\n")
        self.pid = info_agent[0].split(" ")[-1]
        self.ssh_auth_sock = info_agent[1]
        os.environ["SSH_AGENT_PID"] = self.pid
        os.environ["SSH_AUTH_SOCK"] = self.ssh_auth_sock

    def __exit__(self, type, value, traceback):
        # never kill previously started ssh-agent, so that user only has to
        # enter private key password once
        pass


class WrapperSingletoneSshTunnel(object):

    def __init__(self,
                 interval_ssh="9000-9999",
                 locker=multiprocessing.Lock()):
        self.interval_ssh = [int(interval_ssh.split('-')[0]),
                             int(interval_ssh.split('-')[1])]
        self.busy_port = []
        self.locker = locker

    def get_free_port(self):
        with self.locker:
            beg = self.interval_ssh[0]
            end = self.interval_ssh[1]
            while beg <= end:
                if beg not in self.busy_port:
                    self.busy_port.append(beg)
                    return beg
                beg += 1
        raise RuntimeError("No free ssh port")

    def free_port(self, port):
        with self.locker:
            if port in self.busy_port:
                self.busy_port.remove(port)

    def __call__(self, address_dest_compute, address_dest_controller, host,
                 **kwargs):
        return UpSshTunnelClass(address_dest_compute,
                                address_dest_controller,
                                host,
                                self.get_free_port,
                                self.free_port)


class UpSshTunnelClass(object):
    """Up ssh tunniel on dest controller node for transferring data."""

    def __init__(self, address_dest_compute, address_dest_controller, host,
                 callback_get, callback_free):
        self.address_dest_compute = address_dest_compute
        self.address_dest_controller = address_dest_controller
        self.get_free_port = callback_get
        self.remove_port = callback_free
        self.host = host
        self.cmd = SSH_CMD

    def __enter__(self):
        self.port = self.get_free_port()
        with settings(host_string=self.host,
                      connection_attempts=env.connection_attempts):
            run(self.cmd % (self.port,
                            self.address_dest_compute,
                            self.port,
                            self.port,
                            self.address_dest_controller) + " && sleep 2")
        return self.port

    def __exit__(self, type, value, traceback):
        with settings(host_string=self.host,
                      connection_attempts=env.connection_attempts):
            run(("pkill -f '" + self.cmd + "'") %
                (self.port,
                 self.address_dest_compute,
                 self.port,
                 self.port,
                 self.address_dest_controller))
        time.sleep(2)
        self.remove_port(self.port)


def libvirt_instance_exists(libvirt_name, init_host, compute_host, ssh_user,
                            ssh_sudo_password):
    with settings(host_string=compute_host,
                  user=ssh_user,
                  password=ssh_sudo_password,
                  gateway=init_host,
                  connection_attempts=env.connection_attempts,
                  warn_only=True,
                  quiet=True):
        out = sudo('virsh domid %s' % libvirt_name)
        return out.succeeded


def get_libvirt_block_info(libvirt_name, init_host, compute_host, ssh_user,
                           ssh_sudo_password):
    with settings(host_string=compute_host,
                  user=ssh_user,
                  password=ssh_sudo_password,
                  gateway=init_host,
                  connection_attempts=env.connection_attempts):
        out = sudo("virsh domblklist %s" % libvirt_name)
        libvirt_output = out.split()
    return libvirt_output


def find_element_by_in(list_values, word):
    for i in list_values:
        if word in i:
            return i


def init_singletones(cfg):
    globals()['up_ssh_tunnel'] = WrapperSingletoneSshTunnel(
        cfg.migrate.ssh_transfer_port)


def get_disk_path(instance, blk_list, is_ceph_ephemeral=False, disk=DISK):
    disk_path = None
    if not is_ceph_ephemeral:
        disk = "/" + disk
        for i in blk_list:
            if instance.id + disk == i[-(LEN_UUID_INSTANCE + len(disk)):]:
                disk_path = i
            if instance.name + disk == i[-(len(instance.name) + len(disk)):]:
                disk_path = i
    else:
        disk = "_" + disk
        for i in blk_list:
            if ("compute/%s%s" % (instance.id, disk)) == i:
                disk_path = i
    return disk_path


def get_ips(init_host, compute_host, ssh_user):
    with settings(host_string=compute_host,
                  user=ssh_user,
                  gateway=init_host,
                  connection_attempts=env.connection_attempts):
        cmd = ("ifconfig | awk -F \"[: ]+\" \'/inet addr:/ "
               "{ if ($4 != \"127.0.0.1\") print $4 }\'")
        out = run(cmd)
        list_ips = []
        for info in out.split():
            try:
                ipaddr.IPAddress(info)
            except ValueError:
                continue
            list_ips.append(info)
    return list_ips


def get_ext_ip(ext_cidr, init_host, compute_host, ssh_user):
    list_ips = get_ips(init_host, compute_host, ssh_user)
    for ip_str in list_ips:
        ip_addr = ipaddr.IPAddress(ip_str)
        for cidr in ext_cidr:
            if ipaddr.IPNetwork(cidr.strip()).Contains(ip_addr):
                return ip_str
    return None


def check_file(file_path):
    return file_path is not None and os.path.isfile(file_path)


def read_yaml_file(yaml_file_path):
    if not check_file(yaml_file_path):
        return None
    with open(yaml_file_path) as yfile:
        return yaml.load(yfile)


def write_yaml_file(file_name, content):
    with open(file_name, 'w') as yfile:
        yaml.safe_dump(content, yfile)


def timer(func, *args, **kwargs):
    t = timeit.Timer(lambda: func(*args, **kwargs))
    elapsed = t.timeit(number=1)
    return elapsed


def import_class_by_string(name):
    """ This function takes string in format
        'cloudferrylib.os.storage.cinder_storage.CinderStorage'
        And returns class object.
    """

    module, class_name = name.split('.')[:-1], name.split('.')[-1]
    mod = __import__(".".join(module))
    for comp in module[1:]:
        mod = getattr(mod, comp)
    return getattr(mod, class_name)
