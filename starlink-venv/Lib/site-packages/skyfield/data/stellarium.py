"""Parse Stellarium data files."""

import json
from collections import namedtuple

StarName = namedtuple('StarName', 'hip name')

def parse_constellations(lines):
    """Parse an old-fashioned ``constellationship.fab`` file.

    Stellarium has deprecated this file format.  See the docstring of
    the next function for the structure of the return value.

    """
    constellations = []
    for line in lines:
        line = line.lstrip()
        if line.startswith(b'#'):
            continue
        fields = line.split()
        if not fields:
            continue
        name = fields[0]
        edges = [(int(fields[i]), int(fields[i+1]))
                 for i in range(2, len(fields), 2)]
        constellations.append((name.decode('utf-8'), edges))
    return constellations

def parse_constellations_json(lines):
    """Parse Stellarium ``/skycultures/modern_st/index.json`` constellations.

    The return value is a Python list of tuples, each giving a 3-letter
    constellation abbreviation and a list of line segments to be drawn
    between pairs of stars in that constellation::

        [
            ('And', [(677, 3092), (3092, 5447), ...]),
            ('Ant', [(53502, 51172), (51172, 46515)]),
            ('Aps', [(72370, 81065), (80047, 81852), ...]),
            ...
        ]

    Each star is identified by its integer Hipparcos catalog number.

    """
    j = json.load(lines)
    constellations = []
    for item in j['constellations']:
        name = item['id'][-3:]
        lines = []
        for segment in item['lines']:
            count = len(segment) - 1
            lines.extend((segment[i], segment[i+1]) for i in range(count))
        constellations.append((name, lines))
    return constellations

def parse_star_names(lines):
    """Return the names in a Stellarium ``star_names.fab`` file.

    Returns a list of named tuples, each of which offers a ``.hip``
    attribute with a Hipparcos catalog number and a ``.name`` attribute
    with the star name.  Do not depend on the tuple having only length
    two; additional fields may be added in the future.

    """
    names = []
    for line in lines:
        line = line.strip()
        if line == b'' or line.startswith(b'#'):
            continue
        fields = line.split()
        hip, name = fields[0].split(b'|')
        names.append(StarName(
            int(hip),
            name.strip(b'_(")').decode('utf-8'),
        ))
    return names
