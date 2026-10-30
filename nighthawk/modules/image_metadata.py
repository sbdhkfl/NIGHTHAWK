"""Image metadata intelligence module.

Extracts EXIF metadata from locally uploaded images: camera make/model,
timestamps, GPS coordinates, dimensions and format. Images are never uploaded
to external services.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

from nighthawk.core.config import get_settings
from nighthawk.core.validation import validate_image_filename


def _degrees_minutes_seconds_to_decimal(
    value: tuple, ref: str
) -> float | None:
    """Convert EXIF GPS DMS tuple to decimal degrees."""
    try:
        degrees = float(value[0])
        minutes = float(value[1])
        seconds = float(value[2])
    except (TypeError, ValueError):
        return None
    decimal = degrees + minutes / 60.0 + seconds / 3600.0
    if ref in ("S", "W"):
        decimal = -decimal
    return decimal


def run(image_path: str, session=None) -> list[dict[str, Any]]:
    """Extract EXIF and image metadata from a local image file.

    Returns a list of finding dicts compatible with the investigation engine.
    """
    settings = get_settings()
    filename = validate_image_filename(image_path)

    data_dir = settings.DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)

    # Resolve path safely: only the filename is allowed (no directory traversal).
    # Users place images in the data directory or pass an absolute path within it.
    candidate = data_dir / filename
    if not candidate.exists():
        # Allow explicit absolute/relative paths that resolve inside the data dir.
        resolved = Path(image_path).resolve()  # type: ignore[name-defined]
        if str(resolved).startswith(str(data_dir.resolve())):
            candidate = resolved
        else:
            raise FileNotFoundError(
                f"image not found in data directory ({data_dir}): {filename}"
            )

    if candidate.stat().st_size > settings.MAX_UPLOAD_BYTES:
        raise ValueError(
            f"image exceeds maximum upload size of {settings.MAX_UPLOAD_BYTES} bytes"
        )

    try:
        with Image.open(candidate) as img:
            img.load()
            width, height = img.size
            image_format = img.format
            exif = img.getexif()
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError(f"unable to read image: {exc}") from exc

    metadata: dict[str, Any] = {
        "filename": filename,
        "format": image_format,
        "width": width,
        "height": height,
        "size_bytes": candidate.stat().st_size,
    }

    if exif:
        readable: dict[str, Any] = {}
        gps: dict[str, Any] = {}
        for tag_id, value in exif.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name == "GPSInfo":
                for gps_tag_id, gps_value in value.items():
                    gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                    gps[gps_tag_name] = gps_value
                # Compose decimal coordinates when possible.
                lat = gps.get("GPSLatitude")
                lat_ref = gps.get("GPSLatitudeRef")
                lon = gps.get("GPSLongitude")
                lon_ref = gps.get("GPSLongitudeRef")
                if lat and lat_ref and lon and lon_ref:
                    lat_dec = _degrees_minutes_seconds_to_decimal(lat, lat_ref)
                    lon_dec = _degrees_minutes_seconds_to_decimal(lon, lon_ref)
                    if lat_dec is not None and lon_dec is not None:
                        gps["decimal_latitude"] = lat_dec
                        gps["decimal_longitude"] = lon_dec
                continue
            readable[str(tag_name)] = value

        if readable:
            metadata["exif"] = readable
        if gps:
            metadata["gps"] = gps

    # Camera make/model.
    exif_map = metadata.get("exif", {})
    camera = {}
    if exif_map.get("Make"):
        camera["make"] = exif_map["Make"]
    if exif_map.get("Model"):
        camera["model"] = exif_map["Model"]
    if camera:
        metadata["camera"] = camera

    # Timestamps.
    timestamps = {}
    for key in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
        if exif_map.get(key):
            timestamps[key] = exif_map[key]
    if timestamps:
        metadata["timestamps"] = timestamps

    metadata["gps_metadata_status"] = "present" if metadata.get("gps") else "not_embedded"
    metadata["processing"] = "local_only; image bytes are not sent to search providers"

    return [
        {
            "module": "image_metadata",
            "target": filename,
            "result_data": metadata,
            "source": str(candidate),
            "confidence": "high",
        }
    ]


__all__ = ["run"]
