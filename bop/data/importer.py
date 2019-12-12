import os
import json
import enum
from collections import OrderedDict

__all__ = ['load', 'Res', 'CACHE_SIZE']
__folder__ = os.path.dirname(__file__)
CACHE_SIZE = 4
CACHE = OrderedDict()


class Res(enum.Enum):
    EN_freq_1 = 1

    EN_example_1 = 10  # these are the first lines of Moby Dick


RESOURCES = {
    Res.EN_freq_1: 'freq_en_1.json',
    Res.EN_example_1: 'example_en_1.json'
}


def load(resource_id):
    if resource_id in CACHE:
        return CACHE[resource_id]

    with open(os.path.join(__folder__, RESOURCES[resource_id]), 'r') as f:
        data = json.load(f)
    if len(CACHE) >= CACHE_SIZE:
        oldest = next(iter(CACHE.keys()))
        CACHE.pop(oldest)

    CACHE[resource_id] = data

    return data
