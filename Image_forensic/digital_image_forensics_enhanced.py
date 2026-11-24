import hashlib
import io
import json
import os
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

from PIL import Image, ImageChops, ImageEnhance, ExifTags, ImageTk

APP_TITLE = "Digital Image Forensics and Tampering Detection Tool"
ELA_SCALE = 10
HIGH_ERROR_THRESHOLD = 20


def sha_hash(path, algorithm="sha256"):
    digest = hashlib.new(algorithm)
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identify_signature(data):
    signatures = [
        (b"\xff\xd8\xff", "JPEG"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"BM", "BMP"),
        (b"II*\x00", "TIFF"),
        (b"MM\x00*", "TIFF"),
    ]
    for signature, name in signatures:
        if data.startswith(signature):
            return name
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "WEBP"
    return "Unknown"


def file_extension_type(path):
    extension = os.path.splitext(path)[1].lower()
    return {
        ".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG",
        ".gif": "GIF", ".bmp": "BMP", ".tif": "TIFF",
        ".tiff": "TIFF", ".webp": "WEBP"
    }.get(extension, extension[1:].upper() if extension else "No extension")


def safe_value(value, limit=300):
    text = str(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def gps_to_degrees(value):
    """Convert EXIF GPS degrees/minutes/seconds to decimal degrees."""
    try:
        parts = []
        for item in value:
            parts.append(float(item))
        return parts[0] + parts[1] / 60 + parts[2] / 3600
    except (TypeError, ValueError, IndexError, ZeroDivisionError):
        return None


def extract_exif(image):
    result = {}
    try:
        exif = image.getexif()
        for tag_id, value in exif.items():
            tag = ExifTags.TAGS.get(tag_id, str(tag_id))
            result[tag] = safe_value(value)

        # GPS is stored in a nested IFD in many JPEG files.
        try:
            gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
            if gps_ifd:
                gps = {
                    ExifTags.GPSTAGS.get(k, str(k)): v
                    for k, v in gps_ifd.items()
                }
                lat = gps_to_degrees(gps.get("GPSLatitude"))
                lon = gps_to_degrees(gps.get("GPSLongitude"))
                if lat is not None and lon is not None:
                    if gps.get("GPSLatitudeRef") == "S":
                        lat = -lat
                    if gps.get("GPSLongitudeRef") == "W":
                        lon = -lon
                    result["GPS Coordinates"] = f"{lat:.6f}, {lon:.6f}"
        except Exception:
            pass
    except Exception as exc:
        result["EXIF Read Error"] = str(exc)
    return result


def create_ela(image, output_path):
    """Create an ELA visualization. ELA is an indicator, not proof of editing."""
    rgb = image.convert("RGB")
    buffer = io.BytesIO()
    rgb.save(buffer, format="JPEG", quality=90)
    buffer.seek(0)

    with Image.open(buffer) as recompressed:
        difference = ImageChops.difference(rgb, recompressed.convert("RGB"))

    enhanced = ImageEnhance.Brightness(difference).enhance(ELA_SCALE)
    enhanced.save(output_path, format="PNG")

    extrema = difference.getextrema()
    max_error = max(channel[1] for channel in extrema)
    grayscale_values = list(difference.convert("L").getdata())
    count = len(grayscale_values)
    mean_error = sum(grayscale_values) / count if count else 0
    high_count = sum(value > HIGH_ERROR_THRESHOLD for value in grayscale_values)
    high_percent = high_count / count * 100 if count else 0

    if high_percent >= 1.0:
        interpretation = (
            "MEDIUM INDICATOR: noticeable localized differences found. "
            "Inspect the ELA image and compare with the original."
        )
    else:
        interpretation = (
            "LOW INDICATOR: few pixels crossed the selected threshold. "
            "This does not prove that the image is original."
        )

    return {
        "maximum_error": max_error,
        "mean_grayscale_error": round(mean_error, 4),
        "threshold": HIGH_ERROR_THRESHOLD,
        "pixels_above_threshold_percent": round(high_percent, 2),
        "interpretation": interpretation,
        "ela_image": output_path,
        "note": "ELA depends on compression history and settings. It is not proof of manipulation."
    }


def analyze_image(path):
    # Capture the original hash before analysis for evidence-integrity checking.
    hash_before = sha_hash(path, "sha256")

    stat = os.stat(path)
    file_size = stat.st_size
    modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    created = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "rb") as file:
        raw = file.read()

    extension_type = file_extension_type(path)
    actual_type = identify_signature(raw[:16])
    signature_match = extension_type == actual_type

    appended_result = "Not applicable: file is not identified as JPEG."
    if actual_type == "JPEG":
        end_marker = raw.rfind(b"\xff\xd9")
        if end_marker == -1:
            appended_result = "JPEG end marker not found."
        elif end_marker + 2 < len(raw):
            appended_bytes = len(raw) - (end_marker + 2)
            appended_result = (
                f"Possible appended data detected: {appended_bytes} byte(s) "
                "after the last JPEG end marker."
            )
        else:
            appended_result = "No data appended after the JPEG end marker."

    with Image.open(path) as image:
        image_format = image.format or "Unknown"
        image_mode = image.mode
        width, height = image.size
        frame_count = getattr(image, "n_frames", 1)
        exif = extract_exif(image)
        image_copy = image.copy()

    ela_path = os.path.splitext(path)[0] + "_ela.png"
    ela_result = None
    if actual_type == "JPEG":
        try:
            ela_result = create_ela(image_copy, ela_path)
        except Exception as exc:
            ela_result = {"error": f"ELA could not be generated: {exc}"}

    # Verify that analysis did not modify the original evidence file.
    hash_after = sha_hash(path, "sha256")
    integrity_verified = hash_before == hash_after

    extension_status = "MATCH" if signature_match else "MISMATCH"
    if actual_type == "Unknown":
        extension_status = "UNKNOWN SIGNATURE"

    report = {
        "report_title": APP_TITLE,
        "generated_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_information": {
            "file_name": os.path.basename(path),
            "full_path": os.path.abspath(path),
            "size_bytes": file_size,
            "created_or_metadata_change_time": created,
            "last_modified": modified
        },
        "image_properties": {
            "format_reported_by_pillow": image_format,
            "detected_file_signature": actual_type,
            "mode": image_mode,
            "width": width,
            "height": height,
            "frames": frame_count
        },
        "hashes": {
            "MD5": sha_hash(path, "md5"),
            "SHA1": sha_hash(path, "sha1"),
            "SHA256_before_analysis": hash_before,
            "SHA256_after_analysis": hash_after
        },
        "integrity_verification": {
            "original_file_unchanged_during_analysis": integrity_verified
        },
        "file_signature_check": {
            "extension_type": extension_type,
            "detected_type": actual_type,
            "result": extension_status
        },
        "trailing_data_check": appended_result,
        "exif_metadata": exif,
        "error_level_analysis": ela_result,
        "limitations": [
            "ELA is an indicator and cannot independently prove image manipulation.",
            "Missing EXIF metadata does not prove that an image is fake.",
            "File timestamps can be changed and should not be treated as conclusive evidence."
        ]
    }

    lines = [
        "=" * 64,
        "DIGITAL IMAGE FORENSIC REPORT",
        "=" * 64,
        f"Generated on: {report['generated_on']}",
        "",
        "1. FILE INFORMATION",
        f"File name: {os.path.basename(path)}",
        f"Full path: {os.path.abspath(path)}",
        f"Size: {file_size} bytes",
        f"Created/metadata-change time: {created}",
        f"Last modified: {modified}",
        "",
        "2. IMAGE PROPERTIES",
        f"Format: {image_format}",
        f"Detected signature: {actual_type}",
        f"Mode: {image_mode}",
        f"Dimensions: {width} x {height}",
        f"Number of frames: {frame_count}",
        "",
        "3. HASH VALUES",
        f"MD5: {report['hashes']['MD5']}",
        f"SHA-1: {report['hashes']['SHA1']}",
        f"SHA-256 before analysis: {hash_before}",
        f"SHA-256 after analysis: {hash_after}",
        f"Integrity verification: {'PASSED' if integrity_verified else 'FAILED'}",
        "",
        "4. FILE SIGNATURE CHECK",
        f"Extension says: {extension_type}",
        f"Detected signature: {actual_type}",
        f"Result: {extension_status}",
        "",
        "5. TRAILING DATA CHECK",
        appended_result,
        "",
        "6. EXIF METADATA"
    ]

    if exif:
        lines.extend([f"{key}: {value}" for key, value in exif.items()])
    else:
        lines.append("No EXIF metadata found.")

    lines.extend(["", "7. ERROR LEVEL ANALYSIS"])
    if ela_result:
        if "error" in ela_result:
            lines.append(ela_result["error"])
        else:
            lines.extend([
                f"Maximum error difference: {ela_result['maximum_error']}",
                f"Mean grayscale error: {ela_result['mean_grayscale_error']}",
                f"Pixels above threshold: {ela_result['pixels_above_threshold_percent']}%",
                f"Preliminary interpretation: {ela_result['interpretation']}",
                f"ELA image saved as: {ela_path}",
                ela_result["note"]
            ])
    else:
        lines.append("ELA is currently performed only for JPEG images.")

    lines.extend([
        "",
        "8. FORENSIC LIMITATIONS",
        *[f"- {item}" for item in report["limitations"]],
        "",
        "This report provides basic educational forensic indicators. "
        "No single result confirms or disproves image tampering."
    ])

    report_text = "\n".join(lines)
    base = os.path.splitext(path)[0]
    txt_path = base + "_forensic_report.txt"
    json_path = base + "_forensic_report.json"

    with open(txt_path, "w", encoding="utf-8") as file:
        file.write(report_text)
    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return report_text, txt_path, json_path, ela_path if ela_result and "error" not in ela_result else None, image_copy


class ForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1120x760")
        self.root.minsize(850, 600)
        self.selected_path = None
        self.preview_photo = None

        header = tk.Label(
            root, text=APP_TITLE,
            font=("Segoe UI", 18, "bold"), fg="#17365D"
        )
        header.pack(pady=(12, 4))

        description = tk.Label(
            root,
            text="Inspect image properties, metadata, hashes, file signatures and JPEG ELA.",
            font=("Segoe UI", 10)
        )
        description.pack(pady=(0, 10))

        controls = tk.Frame(root)
        controls.pack(fill="x", padx=14, pady=5)

        self.path_var = tk.StringVar(value="No image selected")
        tk.Entry(
            controls, textvariable=self.path_var, state="readonly"
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttk.Button(controls, text="Choose Image", command=self.choose_image).pack(side="left")
        ttk.Button(controls, text="Analyze Image", command=self.run_analysis).pack(
            side="left", padx=(8, 0)
        )

        body = tk.PanedWindow(root, orient=tk.HORIZONTAL, sashwidth=6)
        body.pack(fill="both", expand=True, padx=14, pady=12)

        preview_frame = tk.LabelFrame(body, text="Image Preview", padx=8, pady=8)
        body.add(preview_frame, minsize=250, width=300)

        self.preview_label = tk.Label(
            preview_frame, text="Choose an image to preview.",
            wraplength=250, justify="center"
        )
        self.preview_label.pack(expand=True)

        report_frame = tk.LabelFrame(body, text="Forensic Analysis Report", padx=6, pady=6)
        body.add(report_frame, minsize=500)

        self.output = scrolledtext.ScrolledText(
            report_frame, wrap="word", font=("Consolas", 9)
        )
        self.output.pack(fill="both", expand=True)
        self.output.insert("end", "Choose an image and click Analyze Image.\n")

        footer = tk.Label(
            root,
            text="Educational tool only | Preserve the original image as evidence",
            font=("Segoe UI", 9), fg="#555555"
        )
        footer.pack(pady=(0, 8))

    def choose_image(self):
        path = filedialog.askopenfilename(
            title="Select an image",
            filetypes=[
                ("Image files", "*.jpg *.jpeg *.png *.bmp *.gif *.tif *.tiff *.webp"),
                ("All files", "*.*")
            ]
        )
        if not path:
            return

        self.selected_path = path
        self.path_var.set(path)
        try:
            with Image.open(path) as image:
                preview = image.copy()
                preview.thumbnail((260, 260))
            self.preview_photo = ImageTk.PhotoImage(preview)
            self.preview_label.configure(image=self.preview_photo, text="")
        except Exception as exc:
            self.preview_photo = None
            self.preview_label.configure(
                image="", text=f"Preview unavailable:\n{exc}"
            )

    def run_analysis(self):
        if not self.selected_path:
            messagebox.showwarning("No image selected", "Choose an image first.")
            return

        try:
            report_text, txt_path, json_path, ela_path, _ = analyze_image(
                self.selected_path
            )
            self.output.delete("1.0", "end")
            self.output.insert("end", report_text)

            saved_files = f"Text report:\n{txt_path}\n\nJSON report:\n{json_path}"
            if ela_path:
                saved_files += f"\n\nELA image:\n{ela_path}"

            messagebox.showinfo("Analysis complete", saved_files)
        except Exception as exc:
            messagebox.showerror(
                "Analysis failed",
                f"Could not analyze this file.\n\nDetails: {exc}\n\n"
                "Check that it is a supported image and is not locked by another program."
            )


if __name__ == "__main__":
    root = tk.Tk()
    app = ForensicsApp(root)
    root.mainloop()
