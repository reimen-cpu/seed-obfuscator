#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BIP-39 Seedphrase Obfuscator — Aplicación de escritorio 100 % offline.

Permite seleccionar archivos .txt con seedphrases BIP-39, validarlas
completamente (palabras, índices, entropía, checksum SHA-256), aplicar
una transformación aritmética modular con un número secreto proporcionado
por el usuario y generar nuevas seeds BIP-39 válidas en un archivo de salida.

──────────────────────────────────────────────────────────────────────────
Resumen del proceso BIP-39
──────────────────────────────────────────────────────────────────────────

1. Cada palabra del diccionario BIP-39 tiene un índice de 0 a 2047
   (11 bits cada una).

2. Al concatenar los índices en binario se obtiene un flujo de bits cuyo
   largo depende del número de palabras:

       Palabras │ Total bits │ Entropía (ENT) │ Checksum (CS)
       ─────────┼────────────┼────────────────┼──────────────
           12   │    132     │     128        │       4
           15   │    165     │     160        │       5
           18   │    198     │     192        │       6
           21   │    231     │     224        │       7
           24   │    264     │     256        │       8

3. El checksum son los primeros CS bits de SHA-256(entropía).

4. Para "ofuscar" la seed se realiza:
       clave = SHA-256(secreto || contador)  (expandida al largo de la entropía)
       nueva_entropía = entropía XOR clave
   Luego se recalcula el checksum sobre la nueva entropía, produciendo
   una seed BIP-39 válida con el mismo número de palabras.
   XOR es su propia inversa: aplicar la misma operación recupera la original.

Sin dependencias externas — solo stdlib de Python 3.
──────────────────────────────────────────────────────────────────────────
"""

import hashlib
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════
#  Parámetros BIP-39 por número de palabras
# ═══════════════════════════════════════════════════════════════════════
# word_count → (entropy_bits, checksum_bits)
BIP39_PARAMS = {
    12: (128, 4),
    15: (160, 5),
    18: (192, 6),
    21: (224, 7),
    24: (256, 8),
}


# ═══════════════════════════════════════════════════════════════════════
#  Carga de la lista de palabras BIP-39
# ═══════════════════════════════════════════════════════════════════════

def load_wordlist(path: str) -> list[str]:
    """
    Lee el archivo BIP-39 (una palabra por línea) y devuelve una lista
    ordenada de 2048 palabras.  Lanza excepción si el archivo no tiene
    exactamente 2048 entradas.
    """
    with open(path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    if len(words) != 2048:
        raise ValueError(
            f"El archivo de palabras debe contener exactamente 2048 "
            f"entradas, pero tiene {len(words)}."
        )
    return words


# ═══════════════════════════════════════════════════════════════════════
#  Validación completa de una seedphrase
# ═══════════════════════════════════════════════════════════════════════

def validate_seed(mnemonic: str, wordlist: list[str], word_to_idx: dict[str, int]):
    """
    Valida una seedphrase BIP-39 de forma completa:

    1. Verifica que el número de palabras es válido (12/15/18/21/24).
    2. Verifica que cada palabra existe en la lista BIP-39.
    3. Convierte cada palabra a su índice (0-2047, 11 bits).
    4. Reconstruye el flujo binario completo.
    5. Separa la entropía (primeros ENT bits) del checksum (últimos CS bits).
    6. Recalcula SHA-256(entropía) y extrae los primeros CS bits.
    7. Compara el checksum original con el recalculado.

    Retorna (entropy_bytes, ent_bits, cs_bits) si es válida.
    Lanza ValueError con mensaje descriptivo si hay algún error.
    """
    words = mnemonic.strip().split()
    word_count = len(words)

    # ── Paso 1: número de palabras válido ──
    if word_count not in BIP39_PARAMS:
        raise ValueError(
            f"Cantidad de palabras inválida: {word_count}. "
            f"Debe ser 12, 15, 18, 21 o 24."
        )

    ent_bits, cs_bits = BIP39_PARAMS[word_count]

    # ── Paso 2 & 3: verificar palabras y obtener índices ──
    indices = []
    for i, w in enumerate(words, 1):
        if w not in word_to_idx:
            raise ValueError(
                f"Palabra #{i} '{w}' no se encuentra en la lista BIP-39."
            )
        indices.append(word_to_idx[w])

    # ── Paso 4: reconstruir el flujo binario ──
    # Cada índice ocupa 11 bits. El total es word_count * 11 bits.
    total_bits = word_count * 11
    bit_string = ""
    for idx in indices:
        bit_string += format(idx, "011b")

    assert len(bit_string) == total_bits

    # ── Paso 5: separar entropía y checksum ──
    entropy_bits_str = bit_string[:ent_bits]
    checksum_bits_str = bit_string[ent_bits:]

    # Convertir entropía de bits a bytes
    entropy_bytes = int(entropy_bits_str, 2).to_bytes(ent_bits // 8, "big")

    # ── Paso 6: recalcular checksum con SHA-256 ──
    sha256_hash = hashlib.sha256(entropy_bytes).digest()
    # Tomamos los primeros cs_bits del hash (del byte más significativo)
    hash_bits = bin(int.from_bytes(sha256_hash, "big"))[2:].zfill(256)
    expected_checksum = hash_bits[:cs_bits]

    # ── Paso 7: comparar checksums ──
    if checksum_bits_str != expected_checksum:
        raise ValueError(
            f"Checksum incorrecto. "
            f"Esperado: {expected_checksum}, obtenido: {checksum_bits_str}."
        )

    return entropy_bytes, ent_bits, cs_bits


# ═══════════════════════════════════════════════════════════════════════
#  Derivación de clave y transformación de entropía
# ═══════════════════════════════════════════════════════════════════════

def derive_key(secret: str, length: int) -> bytes:
    """
    Deriva una clave pseudoaleatoria de 'length' bytes a partir de
    una clave secreta (cualquier texto UTF-8), usando SHA-256
    iterativo con un contador.

    Esto garantiza difusión completa: cada bit de la clave depende
    del secreto.  Para entropías de 128 bits basta un hash;
    para 256 bits se concatenan dos rondas.

    La clave es determinista: el mismo secreto siempre produce
    la misma clave, lo que permite revertir la operación.
    """
    secret_bytes = secret.encode("utf-8")
    key = b""
    counter = 0
    while len(key) < length:
        h = hashlib.sha256(secret_bytes + counter.to_bytes(4, "big")).digest()
        key += h
        counter += 1
    return key[:length]


def transform_seed(
    entropy_bytes: bytes,
    ent_bits: int,
    cs_bits: int,
    secret: str,
    idx_to_word: list[str],
) -> str:
    """
    Transforma la entropía de una seed BIP-39 usando una clave secreta:

    1. Deriva una clave del mismo largo que la entropía usando
       SHA-256(secreto || contador).  Esto produce una clave
       pseudoaleatoria de difusión completa.
    2. Aplica XOR byte a byte entre la entropía y la clave:
           nueva_entropía = entropía XOR clave
       XOR cambia TODOS los bits, por lo que TODAS las palabras
       de la seed resultante son diferentes a la original.
    3. XOR es su propia inversa:
           entropía = nueva_entropía XOR clave
       Por lo tanto, aplicar la misma transformación con el mismo
       secreto recupera la entropía original.
    4. Recalcula el checksum SHA-256 sobre la nueva entropía.
    5. Concatena nueva entropía + checksum en binario.
    6. Divide en grupos de 11 bits y mapea cada grupo a una palabra.

    Retorna la nueva seedphrase como string de palabras separadas por espacios.
    """
    ent_bytes_len = ent_bits // 8

    # ── 1. Derivar clave del secreto ──
    key = derive_key(secret, ent_bytes_len)

    # ── 2. XOR: difusión completa sobre toda la entropía ──
    new_entropy_bytes = bytes(a ^ b for a, b in zip(entropy_bytes, key))

    # ── 3. Recalcular checksum SHA-256 ──
    sha256_hash = hashlib.sha256(new_entropy_bytes).digest()
    hash_bits = bin(int.from_bytes(sha256_hash, "big"))[2:].zfill(256)
    new_checksum = hash_bits[:cs_bits]

    # ── 4. Reconstruir flujo binario: entropía + checksum ──
    new_entropy_int = int.from_bytes(new_entropy_bytes, "big")
    new_entropy_bits = bin(new_entropy_int)[2:].zfill(ent_bits)
    full_bits = new_entropy_bits + new_checksum

    # ── 5. Dividir en grupos de 11 bits → palabras ──
    word_count = (ent_bits + cs_bits) // 11
    new_words = []
    for i in range(word_count):
        chunk = full_bits[i * 11 : (i + 1) * 11]
        index = int(chunk, 2)
        new_words.append(idx_to_word[index])

    return " ".join(new_words)


# ═══════════════════════════════════════════════════════════════════════
#  Lectura de seeds desde un archivo (horizontal o vertical)
# ═══════════════════════════════════════════════════════════════════════

def parse_seeds_from_file(file_path: str) -> list[str]:
    """
    Lee un archivo .txt y extrae las seedphrases.
    Soporta dos formatos:

    HORIZONTAL — cada línea es una seed completa:
        abandon abandon abandon ... about
        zoo zoo zoo ... wrong

    VERTICAL — una palabra por línea, seeds separadas por líneas vacías:
        abandon
        abandon
        ...
        about
                          ← línea vacía separa seeds
        zoo
        zoo
        ...
        wrong

    Si el archivo tiene una sola palabra por línea SIN líneas vacías
    intermedias, todas las palabras se agrupan como una única seed.

    Retorna una lista de strings, cada uno con las palabras separadas
    por espacios (formato que espera validate_seed).
    """
    with open(file_path, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()

    # Determinar formato: ¿todas las líneas no vacías tienen 1 sola palabra?
    non_empty = [l.strip() for l in raw_lines if l.strip()]
    if not non_empty:
        return []

    all_single_word = all(len(line.split()) == 1 for line in non_empty)

    if not all_single_word:
        # HORIZONTAL: cada línea no vacía es una seed
        return non_empty

    # VERTICAL: agrupar por bloques separados por líneas vacías
    groups: list[list[str]] = []
    current_group: list[str] = []

    for line in raw_lines:
        word = line.strip()
        if word:
            current_group.append(word)
        else:
            if current_group:
                groups.append(current_group)
                current_group = []
    if current_group:
        groups.append(current_group)

    # Cada grupo es una seed (palabras unidas por espacio)
    return [" ".join(g) for g in groups]


# ═══════════════════════════════════════════════════════════════════════
#  Procesamiento de archivos
# ═══════════════════════════════════════════════════════════════════════

def process_files(
    file_paths: list[str],
    secret: str,
    wordlist: list[str],
    word_to_idx: dict[str, int],
    output_path: str,
    log_fn=None,
):
    """
    Procesa una lista de archivos .txt, cada uno con seedphrases
    (horizontal o vertical).  Genera un archivo de salida con las seeds
    transformadas, etiquetadas con el nombre del archivo de origen.

    log_fn: callable opcional para enviar mensajes de progreso al GUI.
    """

    def log(msg: str):
        if log_fn:
            log_fn(msg)

    output_lines: list[str] = []
    total_processed = 0
    total_errors = 0

    for file_path in file_paths:
        fname = os.path.basename(file_path)
        fname_base = os.path.splitext(fname)[0]  # sin extensión
        log(f"\n📂 Procesando: {fname}")

        # Leer y parsear seeds (horizontal o vertical)
        try:
            seeds = parse_seeds_from_file(file_path)
        except Exception as e:
            log(f"  ⚠ Error al leer el archivo: {e}")
            total_errors += 1
            continue

        if not seeds:
            log("  ⚠ El archivo está vacío o no contiene seeds.")
            total_errors += 1
            continue

        for idx, seed_line in enumerate(seeds, 1):
            word_count = len(seed_line.split())
            # Etiqueta: si hay una sola seed usa el nombre del archivo,
            # si hay varias agrega un número.
            if len(seeds) == 1:
                label = f"{fname_base} ({word_count}w)"
            else:
                label = f"{fname_base} #{idx} ({word_count}w)"

            try:
                # Validar la seed original
                entropy_bytes, ent_bits, cs_bits = validate_seed(
                    seed_line, wordlist, word_to_idx
                )

                # Transformar
                new_seed = transform_seed(
                    entropy_bytes, ent_bits, cs_bits, secret, wordlist
                )

                # Etiqueta + seed transformada al archivo de salida
                output_lines.append(label)
                output_lines.append(new_seed)
                output_lines.append("")

                log(f"  ✅ {label} → transformada correctamente.")
                total_processed += 1

            except ValueError as e:
                # Los errores solo van al log, NO al archivo de salida
                log(f"  ❌ {label}: {e}")
                total_errors += 1

    # Escribir archivo de salida
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines) + "\n")

    log(f"\n✅ Archivo generado: {output_path}")
    log(f"   Seeds correctas: {total_processed}  |  Errores: {total_errors}")

    return total_processed, total_errors


# ═══════════════════════════════════════════════════════════════════════
#  Interfaz gráfica con Tkinter
# ═══════════════════════════════════════════════════════════════════════

class BIP39ObfuscatorApp:
    """Interfaz gráfica para el obfuscador de seedphrases BIP-39."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("BIP-39 Seedphrase Obfuscator")
        self.root.geometry("780x700")
        self.root.resizable(True, True)

        # Intentar centrar la ventana
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"+{x}+{y}")

        # ── Cargar lista de palabras ──
        self.wordlist_path = self._find_wordlist()
        try:
            self.wordlist = load_wordlist(self.wordlist_path)
            self.word_to_idx = {w: i for i, w in enumerate(self.wordlist)}
        except Exception as e:
            messagebox.showerror(
                "Error fatal",
                f"No se pudo cargar la lista BIP-39:\n{e}"
            )
            sys.exit(1)

        self.selected_files: list[str] = []

        self._build_ui()

    # ── Buscar archivo de lista de palabras ──────────────────────────
    def _find_wordlist(self) -> str:
        """
        Busca el archivo de palabras BIP-39 en varias ubicaciones:
        1. Junto al script (mismo directorio).
        2. En el directorio de trabajo actual.
        Soporta los nombres: bip39.txt, english.txt, wordlist.txt
        """
        if getattr(sys, 'frozen', False):
            script_dir = Path(sys._MEIPASS)
        else:
            script_dir = Path(__file__).resolve().parent

        candidates = ["bip39.txt", "english.txt", "wordlist.txt"]

        for name in candidates:
            p = script_dir / name
            if p.is_file():
                return str(p)

        for name in candidates:
            p = Path.cwd() / name
            if p.is_file():
                return str(p)

        messagebox.showerror(
            "Error fatal",
            "No se encontró el archivo de palabras BIP-39.\n"
            "Asegúrate de que 'bip39.txt' (o 'english.txt') esté "
            "en el mismo directorio que este script."
        )
        sys.exit(1)

    # ── Construir la interfaz ────────────────────────────────────────
    def _build_ui(self):
        # Configuración de estilos base
        bg = "#1e1e2e"
        fg = "#cdd6f4"
        accent = "#89b4fa"
        btn_bg = "#313244"
        btn_active = "#45475a"
        entry_bg = "#313244"
        font_main = ("Segoe UI", 10)
        font_title = ("Segoe UI", 14, "bold")
        font_mono = ("Consolas", 9)

        self.root.configure(bg=bg)

        # ── Título ──
        tk.Label(
            self.root,
            text="🔐  BIP-39 Seedphrase Obfuscator",
            font=font_title,
            bg=bg,
            fg=accent,
        ).pack(pady=(15, 5))

        tk.Label(
            self.root,
            text=f"Lista cargada: {os.path.basename(self.wordlist_path)} "
                 f"({len(self.wordlist)} palabras)",
            font=("Segoe UI", 9),
            bg=bg,
            fg="#a6adc8",
        ).pack(pady=(0, 10))

        # ── Marco de archivo(s) ──
        frame_files = tk.Frame(self.root, bg=bg)
        frame_files.pack(fill=tk.X, padx=20, pady=5)

        tk.Label(
            frame_files,
            text="Archivos de seeds (.txt):",
            font=font_main,
            bg=bg,
            fg=fg,
        ).pack(side=tk.LEFT)

        tk.Button(
            frame_files,
            text="Seleccionar archivos…",
            font=font_main,
            bg=btn_bg,
            fg=fg,
            activebackground=btn_active,
            activeforeground=fg,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._select_files,
        ).pack(side=tk.RIGHT)

        # Lista de archivos seleccionados
        self.files_var = tk.StringVar(value="Ningún archivo seleccionado.")
        self.files_label = tk.Label(
            self.root,
            textvariable=self.files_var,
            font=("Segoe UI", 9),
            bg=bg,
            fg="#a6adc8",
            wraplength=700,
            justify=tk.LEFT,
        )
        self.files_label.pack(fill=tk.X, padx=25, pady=(0, 10))

        # ── Clave secreta ──
        self._showing_secret = False  # estado del toggle mostrar/ocultar

        frame_secret = tk.Frame(self.root, bg=bg)
        frame_secret.pack(fill=tk.X, padx=20, pady=(5, 2))

        tk.Label(
            frame_secret,
            text="Clave secreta:",
            font=font_main,
            bg=bg,
            fg=fg,
        ).pack(side=tk.LEFT)

        self.toggle_btn = tk.Button(
            frame_secret,
            text="👁",
            font=("Segoe UI", 10),
            bg=btn_bg,
            fg=fg,
            activebackground=btn_active,
            activeforeground=fg,
            relief=tk.FLAT,
            cursor="hand2",
            width=3,
            command=self._toggle_secret_visibility,
        )
        self.toggle_btn.pack(side=tk.RIGHT, padx=(5, 0))

        self.secret_entry = tk.Entry(
            frame_secret,
            font=font_main,
            bg=entry_bg,
            fg=fg,
            insertbackground=fg,
            relief=tk.FLAT,
            width=36,
            show="•",
        )
        self.secret_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))

        # ── Confirmar clave secreta ──
        frame_confirm = tk.Frame(self.root, bg=bg)
        frame_confirm.pack(fill=tk.X, padx=20, pady=(2, 5))

        tk.Label(
            frame_confirm,
            text="Confirmar clave:",
            font=font_main,
            bg=bg,
            fg=fg,
        ).pack(side=tk.LEFT)

        self.confirm_entry = tk.Entry(
            frame_confirm,
            font=font_main,
            bg=entry_bg,
            fg=fg,
            insertbackground=fg,
            relief=tk.FLAT,
            width=36,
            show="•",
        )
        self.confirm_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))

        # ── Botones: Ofuscar y Revertir ──
        frame_buttons = tk.Frame(self.root, bg=bg)
        frame_buttons.pack(pady=15)

        self.process_btn = tk.Button(
            frame_buttons,
            text="⚡  Ofuscar → output.txt",
            font=("Segoe UI", 11, "bold"),
            bg=accent,
            fg="#1e1e2e",
            activebackground="#b4d0fb",
            activeforeground="#1e1e2e",
            relief=tk.FLAT,
            cursor="hand2",
            command=lambda: self._run(mode="ofuscar"),
            padx=20,
            pady=8,
        )
        self.process_btn.pack(side=tk.LEFT, padx=(0, 10))

        revert_color = "#f38ba8"  # rosa para distinguir
        self.revert_btn = tk.Button(
            frame_buttons,
            text="🔄  Revertir → revert.txt",
            font=("Segoe UI", 11, "bold"),
            bg=revert_color,
            fg="#1e1e2e",
            activebackground="#f5a0b8",
            activeforeground="#1e1e2e",
            relief=tk.FLAT,
            cursor="hand2",
            command=lambda: self._run(mode="revertir"),
            padx=20,
            pady=8,
        )
        self.revert_btn.pack(side=tk.LEFT)

        # ── Consola de log ──
        tk.Label(
            self.root,
            text="Registro de operaciones:",
            font=font_main,
            bg=bg,
            fg=fg,
        ).pack(anchor=tk.W, padx=20)

        self.log_area = scrolledtext.ScrolledText(
            self.root,
            font=font_mono,
            bg="#11111b",
            fg="#a6e3a1",
            insertbackground=fg,
            relief=tk.FLAT,
            height=14,
            state=tk.DISABLED,
        )
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=20, pady=(5, 15))

    # ── Mostrar/ocultar clave secreta ──────────────────────────────────
    def _toggle_secret_visibility(self):
        """Alterna entre mostrar y ocultar el texto de los campos de clave."""
        self._showing_secret = not self._showing_secret
        if self._showing_secret:
            self.secret_entry.configure(show="")
            self.confirm_entry.configure(show="")
            self.toggle_btn.configure(text="🙈")
        else:
            self.secret_entry.configure(show="•")
            self.confirm_entry.configure(show="•")
            self.toggle_btn.configure(text="👁")

    # ── Selección de archivos ────────────────────────────────────────
    def _select_files(self):
        files = filedialog.askopenfilenames(
            title="Seleccionar archivos de seedphrases",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos", "*.*")],
        )
        if files:
            self.selected_files = list(files)
            names = [os.path.basename(f) for f in self.selected_files]
            self.files_var.set(f"{len(names)} archivo(s): {', '.join(names)}")
        else:
            self.selected_files = []
            self.files_var.set("Ningún archivo seleccionado.")

    # ── Log al área de texto ─────────────────────────────────────────
    def _log(self, msg: str):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)
        self.log_area.configure(state=tk.DISABLED)
        self.root.update_idletasks()

    # ── Procesar (ofuscar o revertir) ─────────────────────────────────
    def _run(self, mode: str = "ofuscar"):
        """
        mode="ofuscar"  → aplica  +secreto, genera output.txt
        mode="revertir" → aplica  -secreto, genera revert.txt
        """
        # Limpiar log
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.delete("1.0", tk.END)
        self.log_area.configure(state=tk.DISABLED)

        # Validar que haya archivos seleccionados
        if not self.selected_files:
            messagebox.showwarning(
                "Sin archivos",
                "Selecciona al menos un archivo .txt con seedphrases."
            )
            return

        # Validar la clave secreta
        secret = self.secret_entry.get()
        confirm = self.confirm_entry.get()
        if not secret:
            messagebox.showwarning(
                "Sin clave secreta",
                "Ingresa una clave secreta (texto, números, símbolos…)."
            )
            return
        if secret != confirm:
            messagebox.showerror(
                "Clave no coincide",
                "La clave secreta y la confirmación no coinciden."
            )
            return

        # Determinar archivo de salida según el modo
        # (XOR es su propia inversa, no se necesita negar el secreto)
        if mode == "revertir":
            out_filename = "revert.txt"
            action_label = "REVERSIÓN"
        else:
            out_filename = "output.txt"
            action_label = "RESULTADO"

        output_dir = str(Path(__file__).resolve().parent)
        output_path = os.path.join(output_dir, out_filename)

        self._log(f"🔐 BIP-39 Seedphrase Obfuscator — {action_label}")
        self._log(f"   Clave secreta: {'•' * len(secret)}  ({len(secret)} caracteres)")
        self._log(f"   Archivos: {len(self.selected_files)}")

        # Deshabilitar botones durante el proceso
        self.process_btn.configure(state=tk.DISABLED)
        self.revert_btn.configure(state=tk.DISABLED)

        try:
            ok, errors = process_files(
                file_paths=self.selected_files,
                secret=secret,
                wordlist=self.wordlist,
                word_to_idx=self.word_to_idx,
                output_path=output_path,
                log_fn=self._log,
            )

            if ok > 0:
                messagebox.showinfo(
                    "Completado",
                    f"{'Reversión' if mode == 'revertir' else 'Ofuscación'} finalizada.\n\n"
                    f"Seeds transformadas: {ok}\n"
                    f"Errores: {errors}\n\n"
                    f"Archivo generado:\n{output_path}"
                )
            else:
                messagebox.showwarning(
                    "Sin resultados",
                    f"No se transformó ninguna seed.\n"
                    f"Errores encontrados: {errors}\n\n"
                    f"Revisa el registro para más detalles."
                )
        except Exception as e:
            self._log(f"\n⚠ Error inesperado: {e}")
            messagebox.showerror("Error", f"Error inesperado:\n{e}")
        finally:
            self.process_btn.configure(state=tk.NORMAL)
            self.revert_btn.configure(state=tk.NORMAL)


# ═══════════════════════════════════════════════════════════════════════
#  Punto de entrada principal
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    root = tk.Tk()
    app = BIP39ObfuscatorApp(root)
    root.mainloop()
