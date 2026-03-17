import json
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session
from werkzeug.utils import secure_filename

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})
    access_level = user_info[2]
    if access_level > 2:
        return jsonify({"error": "access level < 2 is required for this action"})
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    filename = secure_filename(filename_param) + ".txt"
    path = Path(user_dir) / filename
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    if name is None:
        return jsonify({"error": "name parameter is required"})

    # Run ps aux without shell=True to prevent command injection
    res = subprocess.run(
        ["ps", "aux"],
        capture_output=True,
    )
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})

    out = res.stdout.decode("utf-8")
    lines = out.split("\n")

    # Filter lines containing the name and extract the 11th column (command)
    names = []
    for line in lines:
        if name in line:
            parts = line.split()
            if len(parts) >= 11:
                names.append(parts[10])  # 0-indexed, so 11th column is index 10

    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    encoded = request.form.get('pickled')
    data = base64.urlsafe_b64decode(encoded)
    deserialized = json.loads(data.decode('utf-8'))
    return jsonify({"success": True, "description": str(deserialized)})
