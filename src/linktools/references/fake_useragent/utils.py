import json

str_types = (str,)


# Load all lines from browser.json file
# Returns array of objects
def load(path):
    data, ret = [], None
    with open(path) as file:
        json_lines = file.read()
        for line in json_lines.splitlines():
            data.append(json.loads(line))
    ret = data

    if not ret:
        raise FakeUserAgentError("Data list is empty", ret)

    if not isinstance(ret, list):
        raise FakeUserAgentError("Data is not a list ", ret)
    return ret


from . import settings  # noqa # isort:skip
from .errors import FakeUserAgentError  # noqa # isort:skip
