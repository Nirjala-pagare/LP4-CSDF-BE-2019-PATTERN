"""
Digital Video Forensics Tool
Educational mini-project for Cyber Security and Digital Forensics.

Features:
- Video metadata extraction
- SHA-256 integrity hashing
- Configurable frame extraction
- Basic sampled-frame difference analysis
- TXT and JSON forensic reports

Run: python video_forensics.py
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import cv2


APP_NAME = "Digital Video Forensics Tool"


def sha256_file(file_path):
    """Calculate SHA-256 without loading the entire video into memory."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as video_file:
        for chunk in iter(lambda: video_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_video(video_path, interval_seconds, output_root):
    """Analyze a video and save extracted evidence plus reports."""
    video_path = Path(video_path)
    capture = cv2.VideoCapture(str(video_path))

    if not capture.isOpened():
        raise RuntimeError("OpenCV could not open this video file.")

    fps = capture.get(cv2.CAP_PROP_FPS)
    frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
    width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
    duration = frame_count / fps if fps and fps > 0 else 0

    output_dir = Path(output_root) / (
        f"{video_path.stem}_evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    frames_dir = output_dir / "extracted_frames"
    frames_dir.mkdir(parents=True, exist_ok=True)

    extracted = []
    frame_differences = []
    previous_gray = None
    interval_frames = max(1, int(round((fps if fps > 0 else 1) * interval_seconds)))
    frame_index = 0
    saved_index = 0

    try:
        while True:
            success, frame = capture.read()
            if not success:
                break

            if frame_index % interval_frames == 0:
                timestamp = frame_index / fps if fps > 0 else 0
                filename = f"frame_{saved_index:04d}_at_{timestamp:.2f}s.jpg"
                frame_path = frames_dir / filename

                if not cv2.imwrite(str(frame_path), frame):
                    raise RuntimeError(f"Could not save extracted frame: {filename}")

                current_gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                difference_score = None
                if previous_gray is not None:
                    # Mean absolute pixel difference, useful as a basic visual-change indicator.
                    difference_score = round(
                        float(cv2.absdiff(previous_gray, current_gray).mean()), 4
                    )
                    frame_differences.append({
                        "frame": filename,
                        "timestamp_seconds": round(timestamp, 3),
                        "mean_absolute_difference": difference_score
                    })

                extracted.append({
                    "filename": filename,
                    "timestamp_seconds": round(timestamp, 3),
                    "sha256": sha256_file(frame_path),
                    "mean_absolute_difference_from_previous_sample": difference_score
                })
                previous_gray = current_gray
                saved_index += 1

            frame_index += 1
    finally:
        capture.release()

    video_hash = sha256_file(video_path)
    report = {
        "project": APP_NAME,
        "analysis_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_video": str(video_path.resolve()),
        "source_file_size_bytes": video_path.stat().st_size,
        "source_sha256": video_hash,
        "metadata": {
            "format_note": "Container/codec details are not decoded by this basic tool.",
            "width_pixels": width,
            "height_pixels": height,
            "resolution": f"{width}x{height}",
            "fps": round(fps, 3) if fps > 0 else None,
            "total_frames_reported": frame_count,
            "duration_seconds": round(duration, 3),
            "duration_hms": (
                f"{int(duration // 3600):02d}:"
                f"{int((duration % 3600) // 60):02d}:"
                f"{int(duration % 60):02d}"
            )
        },
        "analysis_settings": {
            "frame_extraction_interval_seconds": interval_seconds,
            "sampled_frames_saved": len(extracted)
        },
        "extracted_frames": extracted,
        "frame_difference_analysis": frame_differences,
        "limitations": [
            "Frame difference scores indicate visual change, not proof of tampering.",
            "Metadata and hashes alone cannot establish authenticity or identify an editor.",
            "The original video is not modified; extracted frames are analysis copies."
        ]
    }

    json_path = output_dir / "forensic_report.json"
    txt_path = output_dir / "forensic_report.txt"

    with open(json_path, "w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4)

    with open(txt_path, "w", encoding="utf-8") as report_file:
        meta = report["metadata"]
        report_file.write(
            f"{APP_NAME}\n"
            f"{'=' * 60}\n"
            f"Analysis time (UTC): {report['analysis_timestamp_utc']}\n"
            f"Source video: {report['source_video']}\n"
            f"File size: {report['source_file_size_bytes']} bytes\n"
            f"SHA-256: {video_hash}\n\n"
            f"VIDEO METADATA\n{'-' * 60}\n"
            f"Resolution: {meta['resolution']}\n"
            f"FPS: {meta['fps']}\n"
            f"Total frames: {meta['total_frames_reported']}\n"
            f"Duration: {meta['duration_hms']} ({meta['duration_seconds']} seconds)\n\n"
            f"FRAME EXTRACTION\n{'-' * 60}\n"
            f"Interval: {interval_seconds} seconds\n"
            f"Frames extracted: {len(extracted)}\n"
            f"Evidence folder: {frames_dir}\n\n"
            f"EXTRACTED FRAMES\n{'-' * 60}\n"
        )
        for item in extracted:
            report_file.write(
                f"{item['filename']} | {item['timestamp_seconds']} sec | "
                f"SHA-256: {item['sha256']}\n"
            )
        report_file.write(
            "\nLIMITATIONS\n"
            + "\n".join(f"- {item}" for item in report["limitations"])
            + "\n"
        )

    return report, output_dir


class VideoForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("760x570")
        self.root.minsize(650, 480)
        self.video_path = tk.StringVar()
        self.interval = tk.StringVar(value="5")
        self.status = tk.StringVar(value="Select a video to begin.")
        self._build_ui()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=18)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text=APP_NAME, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            main,
            text="Analyze video metadata, preserve evidence, extract frames and create reports.",
            wraplength=700
        ).pack(anchor="w", pady=(4, 16))

        file_frame = ttk.LabelFrame(main, text="Input video", padding=12)
        file_frame.pack(fill="x", pady=5)
        ttk.Entry(file_frame, textvariable=self.video_path).pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        ttk.Button(file_frame, text="Browse", command=self.choose_video).pack(side="right")

        settings = ttk.LabelFrame(main, text="Analysis settings", padding=12)
        settings.pack(fill="x", pady=10)
        ttk.Label(settings, text="Extract one frame every (seconds):").pack(side="left")
        ttk.Entry(settings, textvariable=self.interval, width=8).pack(side="left", padx=10)
        ttk.Label(settings, text="Output is saved in a separate evidence folder.").pack(side="left")

        self.run_button = ttk.Button(main, text="Analyze Video", command=self.start_analysis)
        self.run_button.pack(anchor="w", pady=8)

        ttk.Label(main, text="Activity log", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.log = tk.Text(main, height=13, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True, pady=(5, 8))

        ttk.Label(main, textvariable=self.status).pack(anchor="w")

    def choose_video(self):
        selected = filedialog.askopenfilename(
            title="Select a video",
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mov *.mkv *.wmv *.mpeg *.mpg"),
                ("All files", "*.*")
            ]
        )
        if selected:
            self.video_path.set(selected)
            self.status.set("Video selected. Ready to analyze.")

    def write_log(self, message):
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start_analysis(self):
        path = self.video_path.get().strip()
        try:
            interval = float(self.interval.get())
            if interval <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid interval", "Enter a number greater than zero.")
            return

        if not path or not Path(path).is_file():
            messagebox.showerror("Missing video", "Please select an existing video file.")
            return

        output_root = filedialog.askdirectory(title="Choose where to save forensic evidence")
        if not output_root:
            return

        self.run_button.configure(state="disabled")
        self.status.set("Analysis in progress...")
        self.write_log(f"Starting analysis: {path}")
        threading.Thread(
            target=self._analysis_worker,
            args=(path, interval, output_root),
            daemon=True
        ).start()

    def _analysis_worker(self, path, interval, output_root):
        try:
            report, output_dir = analyze_video(path, interval, output_root)
            summary = (
                f"Analysis completed.\n"
                f"Resolution: {report['metadata']['resolution']}\n"
                f"Duration: {report['metadata']['duration_seconds']} seconds\n"
                f"SHA-256: {report['source_sha256']}\n"
                f"Frames extracted: {len(report['extracted_frames'])}\n"
                f"Reports and evidence: {output_dir}"
            )
            self.root.after(0, lambda: self._analysis_done(summary, output_dir))
        except Exception as error:
            self.root.after(0, lambda: self._analysis_failed(str(error)))

    def _analysis_done(self, summary, output_dir):
        self.write_log(summary)
        self.status.set("Analysis completed successfully.")
        self.run_button.configure(state="normal")
        messagebox.showinfo("Analysis complete", f"{summary}")

    def _analysis_failed(self, error):
        self.write_log(f"ERROR: {error}")
        self.status.set("Analysis failed.")
        self.run_button.configure(state="normal")
        messagebox.showerror("Analysis error", error)


if __name__ == "__main__":
    root = tk.Tk()
    app = VideoForensicsApp(root)
    root.mainloop()
