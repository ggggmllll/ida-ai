"""IDA-side progress journal, separate from the result database/stdout."""
import json
import os
import time


def emit(stage, **values):
    path = os.environ.get('IDA_AI_PROGRESS')
    if path:
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps(dict(stage=stage,time=time.time(),**values))+'\n')
