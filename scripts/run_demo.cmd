@echo off
REM Windows quick-start, after: py -m pip install -e .
cd /d "%~dp0.."
set PYTHONPATH=src
py -m threatweave.cli --db runtime\demo.db demo
py -m threatweave.cli --db runtime\demo.db investigate
pause
