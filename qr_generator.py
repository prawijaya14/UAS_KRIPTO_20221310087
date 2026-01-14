import qrcode

def NPM_20221310087_generate_qr(data: str):
    img = qrcode.make(data)
    img.save("signature_qr.png")
