#!/bin/bash

Path=./factory
cd $Path

python3 fetch_vendor_modules.py
python3 ad.py
python3 gfwlist.py
python3 build_confs.py
