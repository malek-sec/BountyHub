import datetime
import os

from werkzeug.utils import secure_filename


class UploadService:
    ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    MAX_SIZE           = 5 * 1024 * 1024   # 5 MB

    MAGIC_BYTES = [
        (b'\xff\xd8\xff',),            # JPEG
        (b'\x89PNG\r\n\x1a\n',),       # PNG
        (b'GIF87a', b'GIF89a'),        # GIF
    ]

    @staticmethod
    def validate(file) -> bool:
        """
        Check file size and magic bytes.
        Resets the stream to position 0 before returning.
        Returns False for anything that is not a real image.
        WEBP: bytes 0-3 == b'RIFF' and bytes 8-12 == b'WEBP'.
        """
        file.stream.seek(0, 2)
        size = file.stream.tell()
        file.stream.seek(0)
        if size > UploadService.MAX_SIZE:
            return False

        header = file.stream.read(12)
        file.stream.seek(0)

        for sigs in UploadService.MAGIC_BYTES:
            if any(header.startswith(s) for s in sigs):
                return True

        if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
            return True

        return False

    @staticmethod
    def save(file, upload_folder: str) -> str:
        """
        Validate, then save with a timestamped secure_filename.
        Returns the saved filename.
        Raises ValueError if validation fails.
        """
        if not UploadService.validate(file):
            raise ValueError(
                "Invalid file. Only JPEG, PNG, GIF, WEBP under 5 MB are allowed."
            )

        filename = secure_filename(
            f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        )
        os.makedirs(upload_folder, exist_ok=True)
        file.save(os.path.join(upload_folder, filename))
        return filename
