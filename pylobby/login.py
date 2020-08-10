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

import click

import click_log

from .login_server import LoginServer

# Use root logger here, so other loggers inherit the configuration
logger = logging.getLogger()
click_log.basic_config(logger)


@click.command()
@click.option("--user-db", required=True, type=click.Path())
@click_log.simple_verbosity_option(logger)
def main(user_db: str):
    server = LoginServer(user_db)
    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("login server stopped")
