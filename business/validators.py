from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

def validate_image_size(value):
    """
    Validate that the image size is not larger than 2MB.
    """
    filesize = value.size
    if filesize > 2 * 1024 * 1024:
        raise ValidationError(_("El tamaño máximo de la imagen no puede ser superior a 2MB."))

def validate_image_extension(value):
    """
    Validate that the image has a common extension.
    """
    import os
    ext = os.path.splitext(value.name)[1]
    valid_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    if not ext.lower() in valid_extensions:
        raise ValidationError(_(f"Extensión de archivo no válida: {ext}. Extensiones permitidas: {', '.join(valid_extensions)}"))
