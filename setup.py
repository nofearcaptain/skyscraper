#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages

setup(name="skyscraper",
      version="0.0.1",
      description="Scraping the sky and its inhabitants",
      url="https://github.com/nofearcaptain/skyscraper",
      packages=find_packages(),
      install_requires=["pycrypto"]
)
