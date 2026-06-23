
import os
import platform
import subprocess
import time

from config import BASE_DIR

IDS_SCRIPT_PATH = os.path.join(BASE_DIR, "ids_temps_reel.py")
PID_FILE = os.path.join(BASE_DIR, "results", "ids_capture.pid")
_process_handle = None


def _is_windows():
    return platform.system() == "Windows"


def _pid_is_running(pid):
    """Vérifie si un PID correspond à un processus vivant, multiplateforme."""
    if pid is None:
        return False
    try:
        if _is_windows():
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True, text=True, timeout=5,
            )
            return str(pid) in result.stdout
        else:
            os.kill(pid, 0)
            return True
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def _read_pid_file():
    if not os.path.exists(PID_FILE):
        return None
    try:
        with open(PID_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except (ValueError, OSError):
        return None


def _write_pid_file(pid):
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(pid))


def _clear_pid_file():
    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except OSError:
            pass


def _find_running_ids_pid():
   
    if _is_windows():
        ps_command = (
            "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
            "Where-Object { $_.CommandLine -like '*ids_temps_reel.py*' } | "
            "Select-Object -First 1 -ExpandProperty ProcessId"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_command],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout.strip()
            return int(output) if output.isdigit() else None
        except (subprocess.SubprocessError, ValueError):
            return None
    else:
        try:
            result = subprocess.run(
                ["pgrep", "-f", "ids_temps_reel.py"],
                capture_output=True, text=True, timeout=10,
            )
            lines = [l for l in result.stdout.strip().splitlines() if l.strip().isdigit()]
            return int(lines[0]) if lines else None
        except (subprocess.SubprocessError, ValueError):
            return None


def get_status():
    
    pid = _read_pid_file()
    if pid and _pid_is_running(pid):
        return "running", pid

    real_pid = _find_running_ids_pid()
    if real_pid:
        _write_pid_file(real_pid)  # corrige le fichier PID pour la prochaine vérification
        return "running", real_pid

    if pid:
        _clear_pid_file()  # PID périmé, aucun process correspondant trouvé
    return "stopped", None


def _start_windows():
   
    working_dir = BASE_DIR
    ps_command = (
        f"Start-Process -FilePath python "
        f"-ArgumentList '\"{IDS_SCRIPT_PATH}\"' "
        f"-WorkingDirectory '{working_dir}' "
        f"-Verb RunAs -WindowStyle Normal"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_command],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0 and "0x800704C7" not in (result.stderr or ""):
        # 0x800704C7 = l'utilisateur a annulé l'invite UAC ; sinon erreur réelle
        raise RuntimeError(result.stderr.strip() or "Erreur PowerShell inconnue.")


def _start_unix():
   
    process = subprocess.Popen(
        ["sudo", "python3", IDS_SCRIPT_PATH],
        cwd=BASE_DIR,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return process.pid


def start_capture():
  
    status, pid = get_status()
    if status == "running":
        return False, f"La capture est déjà active (PID {pid})."

    if not os.path.exists(IDS_SCRIPT_PATH):
        return False, f"Fichier introuvable : {IDS_SCRIPT_PATH}"

    try:
        if _is_windows():
            _start_windows()
        else:
            _start_unix()
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        return False, f"Échec du démarrage : {e}"

    for _ in range(20):
        time.sleep(1)
        real_pid = _find_running_ids_pid()
        if real_pid:
            _write_pid_file(real_pid)
            return True, f"Capture démarrée (PID {real_pid})."

    return False, (
       
    )


def _force_close_orphan_windows():
   
    if not _is_windows():
        return
    for _ in range(3):
        survivant = _find_running_ids_pid()
        if not survivant:
            return
        try:
            subprocess.run(
                ["taskkill", "/PID", str(survivant), "/T", "/F"],
                capture_output=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return
        time.sleep(0.5)


def stop_capture():
    
    status, pid = get_status()
    if status == "stopped":
        return False, "Aucune capture en cours."

    try:
        if _is_windows():
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=10)
            _force_close_orphan_windows()
        else:
            os.kill(pid, 15)  
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"Échec de l'arrêt : {e}"

    _clear_pid_file()
    return True, f"Capture arrêtée (PID {pid})."
