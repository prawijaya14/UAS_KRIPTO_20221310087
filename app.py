import streamlit as st
import hashlib
import json
import base64
import qrcode
import cv2
import numpy as np
from io import BytesIO
from PIL import Image

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# =========================
# KEY GENERATION (NPM)
# =========================
@st.cache_resource
def npm_20221310087_load_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


private_key, public_key = npm_20221310087_load_keys()


# =========================
# FUNGSI KRIPTO
# =========================
def npm_20221310087_hash_pesan(pesan: str) -> bytes:
    return hashlib.sha256(pesan.encode()).digest()


def npm_20221310087_sign(pesan: str) -> str:
    signature = private_key.sign(
        npm_20221310087_hash_pesan(pesan),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def npm_20221310087_verify(pesan: str, signature_b64: str) -> bool:
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            npm_20221310087_hash_pesan(pesan),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def npm_20221310087_decode_qr(image: Image.Image) -> str | None:
    img = np.array(image.convert("RGB"))
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    return data if data else None


# =========================
# STREAMLIT UI
# =========================
st.set_page_config("UAS Digital Signature QR", "🔐", "centered")
st.title("🔐 UAS Digital Signature QR")
st.caption("RSA + SHA256 | NPM 20221310087")
st.markdown("---")

tab1, tab2 = st.tabs(["📤 PENGIRIM", "📥 PENERIMA"])


# =========================
# TAB PENGIRIM
# =========================
with tab1:
    st.subheader("📤 Pengirim Pesan")

    pesan = st.text_area("Masukkan pesan", height=150)

    if st.button("🔏 Buat QR Digital Signature"):
        if pesan.strip() == "":
            st.warning("Pesan tidak boleh kosong")
        else:
            payload = {
                "pesan": pesan,
                "signature": npm_20221310087_sign(pesan)
            }

            qr_text = json.dumps(payload, ensure_ascii=False)

            qr_img = qrcode.make(qr_text)
            buf = BytesIO()
            qr_img.save(buf)

            st.success("QR berhasil dibuat")
            st.image(buf.getvalue(), width=350)
            st.markdown("### 📦 Isi QR (JSON)")
            st.code(qr_text, language="json")


# =========================
# TAB PENERIMA
# =========================
with tab2:
    st.subheader("📥 Penerima Pesan")

    uploaded = st.file_uploader("Upload gambar QR", type=["png", "jpg", "jpeg"])

    if uploaded:
        image = Image.open(uploaded)
        st.image(image, width=350)

        qr_text = npm_20221310087_decode_qr(image)

        if qr_text:
            st.success("QR berhasil dibaca")
            st.markdown("### 🔍 Isi QR")
            st.code(qr_text, language="json")

            try:
                data = json.loads(qr_text)
                pesan = data["pesan"]
                signature = data["signature"]

                if npm_20221310087_verify(pesan, signature):
                    st.success("✅ TANDA TANGAN VALID")
                    st.markdown("### 📄 Pesan Asli")
                    st.info(pesan)
                else:
                    st.error("❌ TANDA TANGAN TIDAK VALID")

            except Exception as e:
                st.error(f"Format QR tidak valid: {e}")
        else:
            st.error("QR gagal dibaca")
