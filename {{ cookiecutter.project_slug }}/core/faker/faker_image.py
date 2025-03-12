from io import BytesIO
from PIL import Image
from faker.providers import BaseProvider
from django.core.files.base import ContentFile
import base64


class ImageProvider(BaseProvider):
    def image(self):
        image_file = BytesIO()
        image = Image.new("RGBA", size=(50, 50), color=(256, 0, 0))
        image.save(image_file, "png")
        image_file.seek(0)
        return ContentFile(image_file.read(), "test.png")

    def image_base64(self):
        image_file = BytesIO()
        image = Image.new("RGBA", size=(50, 50), color=(256, 0, 0))
        image.save(image_file, "png")
        image_file.seek(0)

        encoded_string = base64.b64encode(image_file.read())

        return encoded_string.decode()
