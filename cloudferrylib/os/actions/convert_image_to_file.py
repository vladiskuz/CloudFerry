from fabric.api import run, settings, env
from cloudferrylib.base import image
from cloudferrylib.base.action import action
from cloudferrylib.utils import utils


class ConvertImageToFile(action.Action):

    def run(self, image_id=None, base_filename=None, **kwargs):
        cfg = self.cloud.cloud_config.cloud
        ssh_attempts = self.cloud.cloud_config.migrate.ssh_connection_attempts

        with settings(host_string=cfg.host, connection_attempts=ssh_attempts):
            with utils.ForwardAgent(env.key_filename):
                cmd = image.glance_image_download_cmd(cfg, image_id,
                                                      base_filename)
                run(cmd)
