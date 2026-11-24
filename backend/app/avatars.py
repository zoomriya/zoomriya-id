"""Profile photos: the user crops in the browser; the server re-encodes.

Only JPEG and PNG are accepted, judged by the file's contents (not its name
or declared type). What arrives is decoded and written back out as a fresh
256px WebP, so nothing from the original file (EXIF, GPS, embedded data) is
kept.
"""

from __future__ import annotations

import io
import os
import uuid
from contextlib import suppress
from pathlib import Path

from PIL import Image, ImageOps, UnidentifiedImageError

from app.config import settings

AVATAR_SIZE = 256
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
# Decompression-bomb guard: plenty for any phone photo.
MAX_PIXELS = 60_000_000
ALLOWED_FORMATS = ("JPEG", "PNG")


class AvatarError(ValueError):
    """The upload isn't a usable image."""


def _root() -> Path:
    return Path(settings.DATA_DIR)


def render_avatar(data: bytes) -> bytes:
    """Decode an uploaded image and return a square 256px WebP."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise AvatarError("That image is too large (10 MB at most)")
    try:
        with Image.open(io.BytesIO(data), formats=ALLOWED_FORMATS) as source:
            if source.width * source.height > MAX_PIXELS:
                raise AvatarError("That image is too large")
            image = ImageOps.exif_transpose(source).convert("RGB")
    except (UnidentifiedImageError, OSError) as exc:
        raise AvatarError("Only JPEG or PNG images can be used as a profile photo") from exc
    # The browser sends an already-cropped square; centre-crop anything else.
    image = ImageOps.fit(image, (AVATAR_SIZE, AVATAR_SIZE), Image.Resampling.LANCZOS)
    out = io.BytesIO()
    image.save(out, "WEBP", quality=85, method=6)
    return out.getvalue()


def save_avatar(user_id: int, webp: bytes) -> str:
    """Write the avatar under <DATA_DIR>/avatars and return its relative path."""
    relative = f"avatars/{user_id}-{uuid.uuid4().hex[:12]}.webp"
    target = _root() / relative
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(webp)
    os.replace(tmp, target)
    return relative


def delete_avatar_file(relative: str | None) -> None:
    if not relative:
        return
    with suppress(OSError):
        (_root() / relative).unlink(missing_ok=True)


def avatar_file(relative: str) -> Path:
    return _root() / relative
