from io import BytesIO
import struct
import zlib
from contextlib import ContextDecorator


class image_open(ContextDecorator):
    def __init__(self, file_or_path):
        if hasattr(file_or_path, "read"):
            self.file = file_or_path
            self.file_pos = self.file.tell()
            self.file.seek(0)
            self.close = False
        else:
            try:
                self.file = open(file_or_path, "rb")
            except OSError:
                self.file = None
            self.close = True

    def __enter__(self):
        return self.file

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if not self.file:
            return

        if self.close:
            self.file.close()
            return

        self.file.seek(self.file_pos)


def get_image_format(file_or_path, close=False):
    """
    Return the format of an image, given an open file or a path.  Set
    'close' to True to close the file at the end if it is initially in an open
    state.
    """
    from PIL import ImageFile as PillowImageFile

    p = PillowImageFile.Parser()

    with image_open(file_or_path) as file:
        if not file:
            return None
        # Most of the time Pillow only needs a small chunk to parse the image
        # and get the dimensions, but with some TIFF files Pillow needs to
        # parse the whole file.
        chunk_size = 1024
        while 1:
            data = file.read(chunk_size)
            if not data:
                break

            try:
                p.feed(data)
            except zlib.error as e:
                # ignore zlib complaining on truncated stream, just feed more
                # data to parser (ticket #19457).
                if e.args[0].startswith("Error -5"):
                    pass
                else:
                    raise
            except struct.error:
                # Ignore PIL failing on a too short buffer when reads return
                # less bytes than expected. Skip and feed more data to the
                # parser (ticket #24544).
                pass
            except RuntimeError:
                # e.g. "RuntimeError: could not create decoder object" for
                # WebP files. A different chunk_size may work.
                pass
            if p.image:
                return p.image.format
            chunk_size *= 2
        return None


def rotate_image(file_or_path, angle: float):
    from PIL import Image

    image = Image.open(file_or_path)
    image_format = image.format
    image = image.rotate(angle, expand=True)

    buffer = BytesIO()
    image.save(buffer, image_format)
    return buffer
