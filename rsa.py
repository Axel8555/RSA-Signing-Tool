import tkinter as tk
from tkinter import filedialog, messagebox, Text, Scrollbar
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64, os, subprocess


# Global variables to store the last used file and mode of operation
last_file_path = ""

def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    return private_key


def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key


def sign_file(file_path, private_key_path):
    global last_file_path
    if not verify_parameters(file_path, private_key_path):
        return
    try:
        private_key = load_private_key(private_key_path)
        content = read_file(file_path)
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(content)
        hash_value = digest.finalize()
        signature = private_key.sign(
            hash_value,
            padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=0),
            hashes.SHA3_256(),
        )
        encoded_signature = base64.b64encode(signature)
        last_file_path = write_file(file_path, content + b"\n" + encoded_signature, "fRSA")
        messagebox.showinfo("Signature", "File signed successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign the file.\n{e}")


def verify_signature(file_path, public_key_path):
    if not verify_parameters(file_path, public_key_path):
        return
    try:
        public_key = load_public_key(public_key_path)
        content = read_file(file_path)
        _, plaintext, signature_base64 = extract_content(content, 0, 345)
        signature = base64.b64decode(signature_base64.strip())
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(plaintext)
        hash_value = digest.finalize()
        public_key.verify(
            signature,
            hash_value,
            padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=0),
            hashes.SHA3_256(),
        )
        messagebox.showinfo("Verification", "The signature is valid :)")
    except Exception as e:
        messagebox.showinfo("Verification", f"Signature verification failed :(\n{e}")


def verify_parameters(file_path, key):
    root = tk.Tk()
    root.withdraw()  # Hide the main Tkinter window
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file.")
        return False
    if not os.path.exists(file_path):
        messagebox.showwarning("Warning", "The file does not exist.")
        return False
    if not key:
        messagebox.showwarning("Warning", "Please select a key.")
        return False
    if not os.path.exists(key):
        messagebox.showwarning("Warning", "The key does not exist.")
        return False
    return True


def extract_content(content, header_size, footer_size):
    if content is not None:
        header = content[:header_size] if header_size > 0 else b""
        footer = content[-footer_size:] if footer_size > 0 else b""
        data = (
            content[header_size:-footer_size]
            if footer_size > 0
            else content[header_size:]
        )
        return header, data, footer
    else:
        return None, None, None


def read_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"Error reading the file: {e}")
        messagebox.showwarning("Read error", f"Error reading the file. {e}")
        return None


def write_file(file_path, data, sufix=None):
    file_path_base = file_path.rsplit(".", 1)[-2]
    extension = file_path.rsplit(".", 1)[-1]
    new_file_path = (
        f"{file_path_base}{('_' + sufix) if sufix is not None else ''}.{extension}"
    )
    try:
        with open(new_file_path, "wb") as f:
            f.write(data)
        print(f"File saved as: {new_file_path}")
        messagebox.showinfo(
            "File saved",
            f"File saved as: {os.path.basename(new_file_path)}",
        )
        subprocess.run(["start", new_file_path], shell=True)
        return new_file_path
    except Exception as e:
        print(f"Error saving the file: {e}")
        messagebox.showwarning("Save error", f"Error saving the file. {e}")
        return None


def main_menu():
    main_menu_window = tk.Tk()
    main_menu_window.title("RSA Signing Tool")
    main_menu_window.geometry("400x100")

    # Central container for buttons
    button_frame = tk.Frame(main_menu_window)
    button_frame.pack(pady=30)  # Center the frame vertically and add some padding

    # Encrypt button
    tk.Button(
        button_frame,
        text="Sign",
        command=lambda: sign_verify_menu(main_menu_window, "Sign"),
        bg="#ff7e38",
        width=10,
    ).pack(
        side=tk.LEFT, padx=10
    )  # Add horizontal spacing between buttons

    # Decrypt button
    tk.Button(
        button_frame,
        text="Verify",
        command=lambda: sign_verify_menu(main_menu_window, "Verify"),
        bg="#38b9ff",
        width=10,
    ).pack(
        side=tk.LEFT, padx=10
    )  # Add horizontal spacing between buttons

    main_menu_window.mainloop()


def sign_verify_menu(parent_window, action):
    parent_window.withdraw()
    action_window = tk.Toplevel()
    action_window.title(f"{action} File")
    action_window.geometry("400x300")

    frame = tk.Frame(action_window)
    frame.pack(padx=10, pady=10)


    # File path
    tk.Label(frame, text="File path:").pack(anchor="w")
    file_path_text = Text(frame, height=1, width=40)
    file_path_text.pack(fill="x", expand=True)
    file_path_text.insert(tk.END, last_file_path)
    scrollbar = Scrollbar(frame, orient="horizontal", command=file_path_text.xview)
    file_path_text.configure(wrap="none", xscrollcommand=scrollbar.set)
    scrollbar.pack(fill="x")
    tk.Button(
        frame, text="Select File", command=lambda: select_file(file_path_text)
    ).pack(anchor="e")

    # Key path
    tk.Label(frame, text="Key path:").pack(anchor="w")
    key_text = Text(frame, height=1, width=40)
    key_text.pack(fill="x", expand=True)
    key_scrollbar = Scrollbar(frame, orient="horizontal", command=key_text.xview)
    key_text.configure(wrap="none", xscrollcommand=key_scrollbar.set)
    key_scrollbar.pack(fill="x")
    tk.Button(frame, text="Select Key", command=lambda: select_file(key_text)).pack(
        anchor="e"
    )

    # Action buttons
    button_frame = tk.Frame(frame)
    button_frame.pack(pady=10)

    if action == "Sign":
        button_text = "Sign File"
        button_color = "#ff7e38"
        command = lambda: sign_file(
            file_path_text.get("1.0", "end-1c"), key_text.get("1.0", "end-1c")
        )
    else:  # Verify
        button_text = "Verify File"
        button_color = "#38b9ff"
        command = lambda: verify_signature(
            file_path_text.get("1.0", "end-1c"), key_text.get("1.0", "end-1c")
        )

    tk.Button(
        button_frame,
        text="Back",
        command=lambda: close_window(action_window, parent_window),
    ).pack(side=tk.LEFT, padx=10, pady=10)
    tk.Button(button_frame, text=button_text, command=command, bg=button_color).pack(
        side=tk.LEFT, padx=10, pady=10
    )


def select_file(text_widget):
    file_path = filedialog.askopenfilename()
    text_widget.delete("1.0", tk.END)
    text_widget.insert("1.0", file_path)


def close_window(child_window, parent_window):
    child_window.destroy()
    parent_window.deiconify()


if __name__ == "__main__":
    main_menu()
