from pyzbar.pyzbar import decode
from PIL import Image

def NPM_20221310087_read_qr(image_file) -> str | None:
    img = Image.open(image_file)
    decoded_objects = decode(img)

    if not decoded_objects:
        return None

    return decoded_objects[0].data.decode("utf-8")
