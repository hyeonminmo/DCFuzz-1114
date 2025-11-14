import json
import logging
import os
import re
from typing import Dict, Optional

import filelock

from . import config as Config



config = Config.CONFIG

logger = logging.getLogger('rcfuzz.coverage')




def sync():

