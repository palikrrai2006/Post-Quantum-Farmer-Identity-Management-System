"""
biometric/sourceafis_bridge.py
================================
Python side of the SourceAFIS bridge. Shells out to the REAL SourceAFIS
engine running inside biometric/java_bridge/target/sourceafis-bridge.jar
(built with Maven — see README "SourceAFIS Setup"). No matching logic is
reimplemented in Python; every score/template below is produced by the
actual com.machinezoo.sourceafis library.

Build once (on your machine, with network access to Maven Central):
    cd biometric/java_bridge
    mvn -q clean package
"""

import base64
import json
import subprocess
import tempfile
import os

import config


class SourceAFISBridgeError(RuntimeError):
    pass


def _require_jar():
    if not os.path.exists(config.SOURCEAFIS_BRIDGE_JAR):
        raise SourceAFISBridgeError(
            f"{config.SOURCEAFIS_BRIDGE_JAR} not found.\n"
            f"Build it first:\n"
            f"  cd biometric/java_bridge\n"
            f"  mvn -q clean package\n"
        )


def extract_template(image_path: str) -> dict:
    """
    Runs: java -jar sourceafis-bridge.jar extract <image_path>

    Returns: {"template_bytes": bytes, "template_size_bytes": int, "extraction_time_ns": int}
    """
    _require_jar()
    try:
        proc = subprocess.run(
            [config.JAVA_EXECUTABLE, "-jar", config.SOURCEAFIS_BRIDGE_JAR, "extract", image_path],
            capture_output=True, text=True, timeout=60, check=True,
        )
    except subprocess.CalledProcessError as e:
        raise SourceAFISBridgeError(f"SourceAFIS extraction failed: {e.stderr}")

    data = json.loads(proc.stdout.strip().splitlines()[-1])
    return {
        "template_bytes": base64.b64decode(data["template_base64"]),
        "template_size_bytes": data["template_size_bytes"],
        "extraction_time_ns": data["extraction_time_ns"],
    }


def match_templates(template1_bytes: bytes, template2_bytes: bytes) -> dict:
    """
    Runs: java -jar sourceafis-bridge.jar match <t1_file> <t2_file>

    Templates are written to temp files (raw serialized SourceAFIS bytes),
    since the bridge jar takes file paths, not stdin blobs.

    Returns: {"score": float, "match_time_ns": int}
    """
    _require_jar()
    with tempfile.NamedTemporaryFile(delete=False) as f1, tempfile.NamedTemporaryFile(delete=False) as f2:
        f1.write(template1_bytes)
        f2.write(template2_bytes)
        path1, path2 = f1.name, f2.name

    try:
        proc = subprocess.run(
            [config.JAVA_EXECUTABLE, "-jar", config.SOURCEAFIS_BRIDGE_JAR, "match", path1, path2],
            capture_output=True, text=True, timeout=60, check=True,
        )
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        return {"score": data["score"], "match_time_ns": data["match_time_ns"]}
    except subprocess.CalledProcessError as e:
        raise SourceAFISBridgeError(f"SourceAFIS matching failed: {e.stderr}")
    finally:
        os.remove(path1)
        os.remove(path2)


if __name__ == "__main__":
    try:
        _require_jar()
        print("SourceAFIS bridge jar found at", config.SOURCEAFIS_BRIDGE_JAR)
    except SourceAFISBridgeError as e:
        print(e)
