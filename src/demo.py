import dearpygui.dearpygui as dpg
from aes_gcm import EncryptedBundle, decrypt, encrypt, generate_key, AuthenticationError

# ── state ────────────────────────────────────────────────────────────────────
_current_key: bytes | None = None
_current_bundle: EncryptedBundle | None = None


# ── helpers ──────────────────────────────────────────────────────────────────

def _set_status(msg: str, error: bool = False) -> None:
    dpg.set_value("status", msg)
    dpg.configure_item("status", color=[220, 80, 80] if error else [100, 220, 140])


def _clear_outputs() -> None:
    for tag in ("out_key", "out_nonce", "out_ct", "out_tag", "out_combined", "out_recovered"):
        dpg.set_value(tag, "")


# ── callbacks ────────────────────────────────────────────────────────────────

def cb_generate_key(*_) -> None:
    global _current_key
    _current_key = generate_key()
    dpg.set_value("out_key", _current_key.hex())
    _set_status("New key generated.")


def cb_encrypt(*_) -> None:
    global _current_bundle
    if _current_key is None:
        _set_status("Generate a key first!", error=True)
        return

    pt_str  = dpg.get_value("in_plaintext")
    aad_str = dpg.get_value("in_aad")

    if not pt_str:
        _set_status("Plaintext is empty.", error=True)
        return

    try:
        plaintext = pt_str.encode("utf-8")
        aad       = aad_str.encode("utf-8") if aad_str else None
        _current_bundle = encrypt(_current_key, plaintext, associated_data=aad)

        dpg.set_value("out_nonce",    _current_bundle.nonce.hex())
        dpg.set_value("out_ct",       _current_bundle.ciphertext.hex())
        dpg.set_value("out_tag",      _current_bundle.tag.hex())
        dpg.set_value("out_combined", _current_bundle.combined().hex())
        dpg.set_value("out_recovered", "")
        _set_status("Encrypted successfully.")
    except Exception as e:
        _set_status(f"Encrypt error: {e}", error=True)


def cb_decrypt(*_) -> None:
    if _current_key is None:
        _set_status("No key loaded.", error=True)
        return

    combined_hex = dpg.get_value("in_combined").strip()
    aad_str      = dpg.get_value("in_aad")

    if combined_hex:
        try:
            bundle = EncryptedBundle.from_combined(bytes.fromhex(combined_hex))
        except Exception as e:
            _set_status(f"Bad combined hex: {e}", error=True)
            return
    elif _current_bundle is not None:
        bundle = _current_bundle
    else:
        _set_status("Nothing to decrypt.", error=True)
        return

    try:
        aad       = aad_str.encode("utf-8") if aad_str else None
        plaintext = decrypt(_current_key, bundle, associated_data=aad)
        dpg.set_value("out_recovered", plaintext.decode("utf-8"))
        _set_status("Decrypted and authenticated successfully.")
    except AuthenticationError:
        dpg.set_value("out_recovered", "")
        _set_status("Authentication FAILED — data tampered or wrong key/AAD!", error=True)
    except Exception as e:
        _set_status(f"Decrypt error: {e}", error=True)


def cb_clear(*_) -> None:
    global _current_bundle
    _current_bundle = None
    for tag in ("in_plaintext", "in_aad", "in_combined"):
        dpg.set_value(tag, "")
    _clear_outputs()
    _set_status("Cleared.")


# ── UI ───────────────────────────────────────────────────────────────────────

def _label(text: str) -> None:
    dpg.add_text(text, color=[180, 180, 210])


def _output_row(label: str, tag: str, width: int = 560) -> None:
    with dpg.group(horizontal=True):
        dpg.add_text(f"{label:<14}", color=[130, 180, 255])
        dpg.add_input_text(tag=tag, width=width, readonly=True,
                           hint="—", multiline=False)


def build_ui() -> None:
    W = 680

    with dpg.window(label="AES-128-GCM", tag="main_win",
                    width=W, height=700, no_close=True):

        dpg.add_text("AES-128-GCM", color=[200, 200, 255])
        dpg.add_separator()
        dpg.add_spacer(height=4)

        # ── Key ──────────────────────────────────────────────────────────────
        _label("KEY")
        with dpg.group(horizontal=True):
            dpg.add_button(label="Generate Key", callback=cb_generate_key,
                           width=130, height=28)
            dpg.add_input_text(tag="out_key", width=490, readonly=True,
                               hint="key hex will appear here")

        dpg.add_spacer(height=8)
        dpg.add_separator()
        dpg.add_spacer(height=6)

        # ── Encrypt ──────────────────────────────────────────────────────────
        _label("ENCRYPT")
        dpg.add_spacer(height=2)

        with dpg.group(horizontal=True):
            dpg.add_text("Plaintext      ", color=[130, 180, 255])
            dpg.add_input_text(tag="in_plaintext", width=490, hint="text to encrypt")

        dpg.add_spacer(height=2)

        with dpg.group(horizontal=True):
            dpg.add_text("AAD            ", color=[130, 180, 255])
            dpg.add_input_text(tag="in_aad", width=490,
                               hint="additional authenticated data (optional)")

        dpg.add_spacer(height=6)
        dpg.add_button(label="Encrypt →", callback=cb_encrypt, width=130, height=28)
        dpg.add_spacer(height=6)

        _output_row("Nonce",     "out_nonce")
        dpg.add_spacer(height=2)
        _output_row("Ciphertext","out_ct")
        dpg.add_spacer(height=2)
        _output_row("Tag",       "out_tag")
        dpg.add_spacer(height=2)
        _output_row("Combined",  "out_combined")

        dpg.add_spacer(height=8)
        dpg.add_separator()
        dpg.add_spacer(height=6)

        # ── Decrypt ──────────────────────────────────────────────────────────
        _label("DECRYPT")
        dpg.add_spacer(height=2)

        with dpg.group(horizontal=True):
            dpg.add_text("Combined hex   ", color=[130, 180, 255])
            dpg.add_input_text(tag="in_combined", width=490,
                               hint="paste combined hex here (or leave blank to use above result)")

        dpg.add_spacer(height=6)
        dpg.add_button(label="← Decrypt", callback=cb_decrypt, width=130, height=28)
        dpg.add_spacer(height=6)

        _output_row("Recovered", "out_recovered")

        dpg.add_spacer(height=10)
        dpg.add_separator()
        dpg.add_spacer(height=4)

        # ── Footer ───────────────────────────────────────────────────────────
        with dpg.group(horizontal=True):
            dpg.add_button(label="Clear All", callback=cb_clear,
                           width=100, height=26)
            dpg.add_spacer(width=10)
            dpg.add_text("", tag="status", color=[100, 220, 140])


def main() -> None:
    dpg.create_context()

    with dpg.font_registry():
        pass  

    with dpg.theme() as global_theme:
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_color(dpg.mvThemeCol_WindowBg,       ( 18,  18,  30))
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg,        ( 32,  32,  52))
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, ( 45,  45,  72))
            dpg.add_theme_color(dpg.mvThemeCol_Button,         ( 60,  80, 180))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered,  ( 80, 110, 220))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive,   ( 50,  60, 160))
            dpg.add_theme_color(dpg.mvThemeCol_Text,           (220, 220, 235))
            dpg.add_theme_color(dpg.mvThemeCol_Border,         ( 60,  60,  90))
            dpg.add_theme_color(dpg.mvThemeCol_Separator,      ( 60,  60,  90))
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding,  6)
            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 8)
            dpg.add_theme_style(dpg.mvStyleVar_FramePadding,   8, 5)
            dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing,    8, 6)

    dpg.bind_theme(global_theme)

    build_ui()

    dpg.create_viewport(title="AES-128-GCM", width=700, height=720,
                        resizable=False)
    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.set_primary_window("main_win", True)
    dpg.start_dearpygui()
    dpg.destroy_context()


if __name__ == "__main__":
    main()