# Standard Library
import logging.config
from contextlib import asynccontextmanager
from os import path

# Third Party
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from setuptools.config.setupcfg import read_configuration as config
from starlette.responses import RedirectResponse
from starlette.status import HTTP_302_FOUND
from tenacity import RetryError

# First Party
from resc_backend.constants import RWS_VERSION_PREFIX
from resc_backend.db.connection import Session, engine
from resc_backend.helpers.environment_wrapper import validate_environment
from resc_backend.resc_web_service.cache_manager import CacheManager
from resc_backend.resc_web_service.configuration import (
    AUTHENTICATION_REQUIRED,
    CORS_ALLOWED_DOMAINS,
    DEBUG_MODE,
    ENABLE_CORS,
    WEB_SERVICE_ENV_VARS,
)
from resc_backend.resc_web_service.dependencies import (
    add_security_headers,
    check_db_initialized,
    log_request_middleware,
    requires_auth,
    requires_no_auth,
)
from resc_backend.resc_web_service.endpoints import (
    common,
    detailed_findings,
    findings,
    health,
    metrics,
    repositories,
    rule_packs,
    rules,
    scans,
    vcs_instances,
)
from resc_backend.resc_web_service.helpers.exception_handler import (
    add_exception_handlers,
)

# Check and load environment variables
env_variables = validate_environment(WEB_SERVICE_ENV_VARS)


def generate_logger_config(log_file_path, debug=True):
    """A function to generate the global logger config dictionary

    Arguments:
        log_file_path {string} -- Path where the logs are to be stored

    Keyword Arguments:
        debug {bool} -- Whether the logging level should be set to DEBUG or INFO (default: {True})

    Returns:
        Dict -- A dictionary containing the logger configuration
    """

    logging_level = "DEBUG" if debug else "INFO"
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "generic-log-formatter": {"format": "[%(levelname)s] [%(name)s] [%(asctime)s] %(message)s"},
        },
        "handlers": {
            "console": {
                "level": logging_level,
                "class": "logging.StreamHandler",
                "formatter": "generic-log-formatter",
            },
            "file": {
                "level": logging_level,
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "generic-log-formatter",
                "filename": log_file_path,
                "maxBytes": 100 * 1024 * 1024,
                "backupCount": 5,
            },
        },
        "loggers": {
            "": {
                "handlers": ["console", "file"],
                "level": logging_level,
                "propagate": True,
            },
        },
    }

    return logging_config


logging.config.dictConfig(generate_logger_config("local_logs.log", False))
logger = logging.getLogger(__name__)
tags_metadata = [
    {"name": "health", "description": "Checks health for API"},
    {"name": "resc-common", "description": "Manage common information"},
    {"name": "resc-rules", "description": "Manage rule information"},
    {"name": "resc-rule-packs", "description": "Manage rule pack information"},
    {"name": "resc-repositories", "description": "Manage repository information"},
    {"name": "resc-scans", "description": "Manage scan information"},
    {"name": "resc-findings", "description": "Manage findings information"},
    {"name": "resc-vcs-instances", "description": "Manage vcs instance information"},
    {"name": "resc-metrics", "description": "Retrieve metrics"},
]

# Check if authentication is required for api endpoints
auth_disabled = env_variables[AUTHENTICATION_REQUIRED].lower() in ["false"]
AUTH = [Depends(requires_no_auth)] if auth_disabled else [Depends(requires_auth)]


@asynccontextmanager
async def lifespan(_: FastAPI):
    app_startup()
    yield
    await app_shutdown()


if path.exists("setup.cfg"):
    read_version = config("setup.cfg")["metadata"]["version"]
else:
    read_version = "3.0.0"

app = FastAPI(
    title="Repository Scanner (RESC)",
    description="RESC API helps you to perform several operations upon findings "
    "obtained from multiple source code repositories.",
    openapi_tags=tags_metadata,
    lifespan=lifespan,
    version=read_version,
)

if env_variables[ENABLE_CORS].lower() in ["true"]:
    origins = env_variables[CORS_ALLOWED_DOMAINS].split(", ")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(health.router, prefix=RWS_VERSION_PREFIX)
app.include_router(common.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)
app.include_router(rules.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)
app.include_router(rule_packs.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)
app.include_router(findings.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)
app.include_router(detailed_findings.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)
app.include_router(repositories.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)
app.include_router(scans.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)
app.include_router(vcs_instances.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)
app.include_router(metrics.router, prefix=RWS_VERSION_PREFIX, dependencies=AUTH)

# Apply the security headers to the app in the form of middleware
app.middleware("http")(log_request_middleware)
app.middleware("http")(add_security_headers)

# Add exception handlers
add_exception_handlers(app=app)


def app_startup():
    CacheManager.initialize_cache(env_variables=env_variables)
    try:
        _ = Session(bind=engine)

        if env_variables[DEBUG_MODE].lower() in ("yes", "y", "true", "t", "1"):
            logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)

        check_db_initialized()

        logger.info("Database is connected, expected table(s) found")
    except RetryError as exc:
        raise SystemExit("Error while connecting to the database, retry timed out") from exc


async def app_shutdown():
    await CacheManager.clear_all_cache()


@app.get("/")
def view_docs():
    return RedirectResponse(url="/docs", status_code=HTTP_302_FOUND)
