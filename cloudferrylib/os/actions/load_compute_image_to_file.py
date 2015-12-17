# FIXME code below is not tested functionally. Should be considered dead

from fabric.api import env
from fabric.api import run
from fabric.api import settings

from cloudferrylib.base import image
from cloudferrylib.base.action import action
from cloudferrylib.utils import utils as utl

INSTANCES = 'instances'
DIFF = 'diff'
EPHEMERAL = 'ephemeral'
DIFF_OLD = 'diff_old'
EPHEMERAL_OLD = 'ephemeral_old'
PATH_DST = 'path_dst'
HOST_DST = 'host_dst'
PATH_SRC = 'path_src'
HOST_SRC = 'host_src'


class LoadComputeImageToFile(action.Action):
    def run(self, info=None, **kwargs):
        cfg = self.cloud.cloud_config.cloud
        ssh_attempts = self.cloud.cloud_config.migrate.ssh_connection_attempts

        for instance_id, instance in info[utl.INSTANCES_TYPE].iteritems():
            inst = info[utl.INSTANCES_TYPE][instance_id][utl.INSTANCE_BODY]
            image_id = inst['image_id']

            base_file = "/tmp/%s" % ("temp%s_base" % instance_id)
            diff_file = "/tmp/%s" % ("temp%s" % instance_id)

            with settings(host_string=cfg.host,
                          connection_attempts=ssh_attempts):
                with utl.ForwardAgent(env.key_filename):
                    cmd = image.glance_image_download_cmd(cfg, image_id,
                                                          base_file)
                    run(cmd)
            instance[DIFF][PATH_DST] = diff_file
            instance[DIFF][HOST_DST] = self.dst_cloud.getIpSsh()
        return {
            'info': info
        }
