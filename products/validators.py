import os

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp']
VIDEO_EXTENSIONS = ['.mp4', '.mov', '.webm']

MAX_IMAGE_SIZE = 5 * 1024 * 1024
MAX_VIDEO_SIZE = 80 * 1024 * 1024


def validate_media_extension(value):
    """
    Validate that a product media file has an allowed image or video extension.
    """
    ext = os.path.splitext(value.name)[1].lower()
    valid_extensions = IMAGE_EXTENSIONS + VIDEO_EXTENSIONS
    if ext not in valid_extensions:
        raise ValidationError(_(
            f"Extensión de archivo no válida: {ext}. Extensiones permitidas: "
            f"{', '.join(IMAGE_EXTENSIONS)} (imágenes), {', '.join(VIDEO_EXTENSIONS)} (video)."
        ))


def validate_media_size(value):
    """
    Validate that a product media file does not exceed the max size for its
    type (image or video), inferred from the file extension.
    """
    ext = os.path.splitext(value.name)[1].lower()
    filesize = value.size
    if ext in VIDEO_EXTENSIONS:
        if filesize > MAX_VIDEO_SIZE:
            raise ValidationError(_("El video supera el peso máximo permitido. Máximo permitido: 80MB."))
    elif filesize > MAX_IMAGE_SIZE:
        raise ValidationError(_("La imagen supera el peso máximo permitido. Máximo permitido: 5MB."))
