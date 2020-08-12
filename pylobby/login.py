#!/usr/bin/env python3

# gs presence server (29900)
# based on works: prmasterserver, miniircd, gsopensdk, aluigi's works
#
#
# RECHECK input info for wrong characters and lengths    CHECK
# 2 TCP SERVER SOCKETs                                   CHECK
# Session number bundled with socket instance            CHECK
# 1 DATABASE FOR USER INFORMATION                        CHECK
# PASSWORD GSBASE64DEC, GSENC, MD5-HASHING PROCEDURES    CHECK
# PASSWORD LOGINCHECK_TRANSFORMATION                     CHECK
# PASSWORD -> PROOF TRANSFORMATION                       CHECK
##<|lc\1 <- (login or newuser)                          CHECK
##>|login -> lc\2                                       CHECK
##>|newuser -> nur                                      CHECK
##<|bdy,blk,bm                                          Not needed
##>|getprofile -> pi                                    Not needed
##>|status ->bdy,blk,bm                                 Not needed
##?|lt                                                  Not needed
##?|ka                                                  Not needed

import logging
import sys

import click
import pkg_resources

import click_log
from prometheus_client import Info

from .login_server import LoginServer

# Use root logger here, so other loggers inherit the configuration
logger = logging.getLogger()
click_log.basic_config(logger)

info = Info("civgs_login", "Civilization 4 lobby/gamebrowser version information")
info.info(
    {
        # https://stackoverflow.com/a/2073599/620382
        "version": pkg_resources.require("civ4-mp.pylobby")[0].version,
        "python_version": sys.version,
    }
)


@click.command()
@click.option("--user-db", required=True, type=click.Path())
@click.option(
    "--prometheus",
    default="",
    help="enable prometheus metrics at given address:port, set to empty to disable",
)
@click_log.simple_verbosity_option(logger)
def main(user_db: str, prometheus: str):
    if prometheus:
        try:
            addr, port_str = prometheus.split(":")
            port = int(port_str)
        except ValueError:
            addr = prometheus
            port = 9147
        logger.info(f"Starting prometheus server on {addr}:{port}")

    server = LoginServer(user_db)
    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("login server stopped")
