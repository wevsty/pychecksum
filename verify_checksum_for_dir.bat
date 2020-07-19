@echo off
call python %~dp0/pychecksum.py --verify_checksum_for_dir %*
pause