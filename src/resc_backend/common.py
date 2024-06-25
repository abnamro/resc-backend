# Standard Library
import logging.config
import sysconfig
from os import path

logger = logging.getLogger(__name__)


def get_logging_settings_path():
    if path.isfile(sysconfig.get_path("purelib") + "/resc"):
        base_dir = sysconfig.get_path("purelib") + "/resc"
    else:
        base_dir = path.dirname(__file__)

    return base_dir + "/static/logging.ini"


def initialise_logs(log_file_path: str, debug: bool = True):
    logging_ini_file = get_logging_settings_path()
    logging.config.fileConfig(
        logging_ini_file,
        defaults={"log_file_path": log_file_path},
        disable_existing_loggers=False,
    )
    logger_config = logging.getLogger("root")
    if debug:
        logger_config.setLevel(logging.DEBUG)
    else:
        logger_config.setLevel(logging.INFO)
    return logger_config
