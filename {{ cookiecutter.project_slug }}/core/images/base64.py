from django.db import models
from PIL import Image
import io
import base64
import uuid


def image_to_base64(image_field: models.ImageField):
    if not image_field:
        return None

    encoded_string = None

    with image_field.open("rb") as input:
        encoded_string = base64.b64encode(input.read())

    if not encoded_string:
        return None

    return encoded_string.decode()


def image_from_base64(image: str):
    byte_data = image.encode()
    decoded = base64.b64decode(byte_data)

    image = Image.open(io.BytesIO(decoded))

    filename = "%s.%s" % (str(uuid.uuid4()), image.format or ".png")
    return io.BytesIO(decoded), filename


__all__ = ["image_to_base64", "image_from_base64"]
