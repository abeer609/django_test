from .source import left, right
import random
import nanoid


def generate_username():
    name = f"{random.choice(left)}_{random.choice(right)}_{nanoid.generate(size=6)}"
    return name
