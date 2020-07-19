@echo off
call python %~dp0/pychecksum.py --create_checksum_for_dir %*
pause