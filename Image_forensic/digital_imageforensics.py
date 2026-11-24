import hashlib
import io
import json
import os
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

from PIL import ExifTags, Image, ImageChops, ImageEnhance, ImageTk

APP_TITLE = "Digital Image Forensics and Tampering Detection Tool"
ELA_SCALE = 10
ELA_THRESHOLD = 20

SIGNATURES = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"BM": "BMP",
    b"II*\x00": "TIFF",
    b"MM\x00*": "TIFF",
}
EXTENSIONS = {
    ".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".gif": "GIF",
    ".bmp": "BMP", ".tif": "TIFF", ".tiff": "TIFF", ".webp": "WEBP",
}


def sha_hash(path, algorithm="sha256"):
    digest = hashlib.new(algorithm)
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_format(data):
    for signature, name in SIGNATURES.items():
        if data.startswith(signature):
            return name
    return "WEBP" if data.startswith(b"RIFF") and data[8:12] == b"WEBP" else "Unknown"


def metadata_value(key, value):
    if key.lower() == "icc_profile" and isinstance(value, bytes):
        return f"Available ({len(value)} bytes)"
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
            if decoded.isprintable() or "\n" in decoded:
                value = decoded
            else:
                return f"Binary data ({len(value)} bytes)"
        except UnicodeDecodeError:
            return f"Binary data ({len(value)} bytes)"
    text = str(value)
    return text if len(text) <= 300 else text[:297] + "..."


def gps_degrees(values):
    try:
        degrees, minutes, seconds = (float(v) for v in values)
        return degrees + minutes / 60 + seconds / 3600
    except (TypeError, ValueError, IndexError, ZeroDivisionError):
        return None


def extract_metadata(image):
    metadata = {}
    try:
        exif = image.getexif()
        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            metadata[f"EXIF - {name}"] = metadata_value(name, value)

        gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
        if gps_ifd:
            gps = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in gps_ifd.items()}
            lat, lon = gps_degrees(gps.get("GPSLatitude")), gps_degrees(gps.get("GPSLongitude"))
            if lat is not None and lon is not None:
                if gps.get("GPSLatitudeRef") == "S":
                    lat = -lat
                if gps.get("GPSLongitudeRef") == "W":
                    lon = -lon
                metadata["GPS Coordinates"] = f"{lat:.6f}, {lon:.6f}"
    except Exception as exc:
        metadata["EXIF Read Error"] = str(exc)

    for key, value in image.info.items():
        metadata[f"Image Info - {key}"] = metadata_value(key, value)
    return metadata


def create_ela(image, output_path):
    original = image.convert("RGB")
    buffer = io.BytesIO()
    original.save(buffer, format="JPEG", quality=90)
    buffer.seek(0)
    with Image.open(buffer) as recompressed:
        difference = ImageChops.difference(original, recompressed.convert("RGB"))

    ImageEnhance.Brightness(difference).enhance(ELA_SCALE).save(output_path)
    maximum = max(channel[1] for channel in difference.getextrema())
    histogram = difference.convert("L").histogram()
    total = sum(histogram)
    mean = sum(value * count for value, count in enumerate(histogram)) / total if total else 0
    high_percent = sum(histogram[ELA_THRESHOLD + 1:]) / total * 100 if total else 0
    interpretation = (
        "MEDIUM INDICATOR: noticeable differences found; inspect and compare with the original."
        if high_percent >= 1 else
        "LOW INDICATOR: few pixels crossed the threshold. This does not prove the image is original."
    )
    return {
        "maximum_error": maximum,
        "mean_grayscale_error": round(mean, 4),
        "threshold": ELA_THRESHOLD,
        "pixels_above_threshold_percent": round(high_percent, 2),
        "interpretation": interpretation,
        "ela_image": output_path,
        "note": "ELA depends on compression history and settings; it cannot prove manipulation.",
    }


def analyze_image(path):
    before = sha_hash(path)
    stat = os.stat(path)
    created = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
    modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "rb") as file:
        raw = file.read()
    extension = EXTENSIONS.get(os.path.splitext(path)[1].lower(), "Unknown")
    detected = detect_format(raw[:16])
    signature_status = "UNKNOWN SIGNATURE" if detected == "Unknown" else (
        "MATCH" if extension == detected else "MISMATCH"
    )

    trailing = "Not applicable: file is not JPEG."
    if detected == "JPEG":
        marker = raw.rfind(b"\xff\xd9")
        trailing = ("JPEG end marker not found." if marker < 0 else
                    f"Possible appended data detected: {len(raw) - marker - 2} byte(s)." if marker + 2 < len(raw) else
                    "No data appended after the JPEG end marker.")

    with Image.open(path) as image:
        properties = {
            "format_reported_by_pillow": image.format or "Unknown",
            "detected_file_signature": detected,
            "mode": image.mode,
            "width": image.width,
            "height": image.height,
            "frames": getattr(image, "n_frames", 1),
        }
        metadata = extract_metadata(image)
        image_copy = image.copy()

    ela_path = os.path.splitext(path)[0] + "_ela.png"
    ela = None
    if detected == "JPEG":
        try:
            ela = create_ela(image_copy, ela_path)
        except Exception as exc:
            ela = {"error": f"ELA could not be generated: {exc}"}

    after = sha_hash(path)
    integrity = before == after
    hashes = {
        "MD5": sha_hash(path, "md5"),
        "SHA1": sha_hash(path, "sha1"),
        "SHA256_before_analysis": before,
        "SHA256_after_analysis": after,
    }
    report = {
        "report_title": APP_TITLE,
        "generated_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_information": {
            "file_name": os.path.basename(path),
            "full_path": os.path.abspath(path),
            "size_bytes": stat.st_size,
            "created_or_metadata_change_time": created,
            "last_modified": modified,
        },
        "image_properties": properties,
        "hashes": hashes,
        "integrity_verification": {"original_file_unchanged_during_analysis": integrity},
        "file_signature_check": {
            "extension_type": extension, "detected_type": detected, "result": signature_status,
        },
        "trailing_data_check": trailing,
        "image_metadata": metadata,
        "error_level_analysis": ela,
        "limitations": [
            "ELA is an indicator and cannot independently prove image manipulation.",
            "Missing metadata does not prove that an image is fake.",
            "Pillow exposes only metadata it recognizes; it is not a complete metadata parser.",
            "File timestamps can be changed and are not conclusive evidence.",
        ],
    }

    lines = [
        "=" * 60, "DIGITAL IMAGE FORENSIC REPORT", "=" * 60,
        f"Generated on: {report['generated_on']}", "", "1. FILE INFORMATION",
        f"File name: {os.path.basename(path)}", f"Full path: {os.path.abspath(path)}",
        f"Size: {stat.st_size} bytes", f"Created/metadata-change time: {created}",
        f"Last modified: {modified}", "", "2. IMAGE PROPERTIES",
        f"Format: {properties['format_reported_by_pillow']}", f"Detected signature: {detected}",
        f"Mode: {properties['mode']}", f"Dimensions: {properties['width']} x {properties['height']}",
        f"Number of frames: {properties['frames']}", "", "3. HASH VALUES",
        *(f"{name}: {value}" for name, value in hashes.items()),
        f"Integrity verification: {'PASSED' if integrity else 'FAILED'}", "",
        "4. FILE SIGNATURE CHECK", f"Extension says: {extension}",
        f"Detected type: {detected}", f"Result: {signature_status}",
        "", "5. TRAILING DATA CHECK", trailing,
        "", "6. EXIF AND ADDITIONAL IMAGE METADATA",
    ]
    lines.extend([f"{key}: {value}" for key, value in metadata.items()] or ["No embedded metadata found."])
    lines += ["", "7. ERROR LEVEL ANALYSIS"]
    if not ela:
        lines.append("ELA is currently performed only for JPEG images.")
    elif "error" in ela:
        lines.append(ela["error"])
    else:
        lines += [
            f"Maximum error difference: {ela['maximum_error']}",
            f"Mean grayscale error: {ela['mean_grayscale_error']}",
            f"Pixels above threshold: {ela['pixels_above_threshold_percent']}%",
            f"Preliminary interpretation: {ela['interpretation']}",
            f"ELA image saved as: {ela_path}", ela["note"],
        ]
    lines += ["", "8. FORENSIC LIMITATIONS", *(f"- {item}" for item in report["limitations"]),
              "", "No single result confirms or disproves image tampering."]

    base = os.path.splitext(path)[0]
    txt_path, json_path = base + "_forensic_report.txt", base + "_forensic_report.json"
    with open(txt_path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))
    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)
    return "\n".join(lines), txt_path, json_path, ela_path if ela and "error" not in ela else None


class ForensicsApp:
    def __init__(self, root):
        self.root, self.selected_path, self.preview_photo = root, None, None
        root.title(APP_TITLE)
        root.geometry("1120x760")
        root.minsize(850, 600)

        tk.Label(root, text=APP_TITLE, font=("Segoe UI", 18, "bold"), fg="#17365D").pack(pady=(12, 4))
        tk.Label(root, text="Inspect image metadata, hashes, file signatures and JPEG ELA.").pack(pady=(0, 10))

        controls = tk.Frame(root)
        controls.pack(fill="x", padx=14, pady=5)
        self.path_var = tk.StringVar(value="No image selected")
        tk.Entry(controls, textvariable=self.path_var, state="readonly").pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(controls, text="Choose Image", command=self.choose_image).pack(side="left")
        ttk.Button(controls, text="Analyze Image", command=self.run_analysis).pack(side="left", padx=(8, 0))

        body = tk.PanedWindow(root, orient=tk.HORIZONTAL, sashwidth=6)
        body.pack(fill="both", expand=True, padx=14, pady=12)
        preview_frame = tk.LabelFrame(body, text="Image Preview", padx=8, pady=8)
        body.add(preview_frame, minsize=250, width=300)
        self.preview_label = tk.Label(preview_frame, text="Choose an image to preview.", wraplength=250)
        self.preview_label.pack(expand=True)
        report_frame = tk.LabelFrame(body, text="Forensic Analysis Report", padx=6, pady=6)
        body.add(report_frame, minsize=500)
        self.output = scrolledtext.ScrolledText(report_frame, wrap="word", font=("Consolas", 9))
        self.output.pack(fill="both", expand=True)
        self.output.insert("end", "Choose an image and click Analyze Image.\n")
        tk.Label(root, text="Educational tool only | Preserve the original image as evidence.", fg="#555555").pack(pady=(0, 8))

    def choose_image(self):
        path = filedialog.askopenfilename(
            title="Select an image",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.gif *.tif *.tiff *.webp"), ("All files", "*.*")],
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
            self.preview_label.configure(image="", text=f"Preview unavailable:\n{exc}")

    def run_analysis(self):
        if not self.selected_path:
            messagebox.showwarning("No image selected", "Choose an image first.")
            return
        try:
            report, txt_path, json_path, ela_path = analyze_image(self.selected_path)
            self.output.delete("1.0", "end")
            self.output.insert("end", report)
            saved = f"Text report:\n{txt_path}\n\nJSON report:\n{json_path}"
            if ela_path:
                saved += f"\n\nELA image:\n{ela_path}"
            messagebox.showinfo("Analysis complete", saved)
        except Exception as exc:
            messagebox.showerror("Analysis failed", f"Could not analyze this file.\n\n{exc}")


if __name__ == "__main__":
    root = tk.Tk()
    ForensicsApp(root)
    root.mainloop()
