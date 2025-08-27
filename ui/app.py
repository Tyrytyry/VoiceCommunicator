
import tkinter as tk
from tkinter import simpledialog, messagebox

import threading
import socket
import hashlib
import os
import vc.network as vc
import vc.audio as audio


#import voice_communicator_modular as vc


class VoiceApp:
    def __init__(self, root: tk.Tk):

        audio.on_call_started = self.on_call_started
        audio.on_call_ended = self.on_call_ended
        self.root = root
        self.root.title("Voice Communicator")
        self.root.geometry("750x400")

        # =======   dane   =======
        self.current_chat_ip = None
        self.msg_entry = None

        self.root.columnconfigure(0, weight=0)   # lista kontaktów – stała szer.
        self.root.columnconfigure(1, weight=1)   # panel przyciski + czat
        self.root.rowconfigure(0, weight=0)      # pasek przycisków
        self.root.rowconfigure(1, weight=1)      # czat (rozciąga się)

        self.contacts_listbox = tk.Listbox(root, font=("Arial", 12), width=25)
        self.contacts_listbox.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=10, pady=10)
        self.contacts_listbox.bind("<<ListboxSelect>>", self.on_contact_select)
        self.refresh_contacts()

        btn_frame = tk.Frame(root)
        btn_frame.grid(row=0, column=1, sticky="nw", padx=(0, 10), pady=10)

        self.call_button = tk.Button(btn_frame, text="Zadzwoń", command=self.call_selected_contact)
        self.call_button.pack(side="left", padx=(0, 10))

        self.add_contact_button = tk.Button(btn_frame, text="Nawiąż kontakt", command=self.open_contact_window)
        self.add_contact_button.pack(side="left", padx=(0, 10))

        self.toggle_listen_button = tk.Button(btn_frame, text="offline", command=self.toggle_listener)
        self.toggle_listen_button.pack(side="left", padx=(0, 10))

        self.delete_contact_button = tk.Button(btn_frame, text="Usuń kontakt", command=self.delete_selected_contact)
        self.delete_contact_button.pack(side="left", padx=(0, 10))

        self.listening = True
        vc.start_listener()
        self._update_online_button(True)

        chat_outer = tk.Frame(root, relief="sunken", bd=1)
        chat_outer.grid(row=1, column=1, sticky="nsew", padx=(0, 10), pady=(0, 10))
        chat_outer.columnconfigure(0, weight=1)
        chat_outer.rowconfigure(0, weight=1)
        chat_outer.rowconfigure(1, weight=0)

        self.chat_text = tk.Text(chat_outer, wrap="word", state=tk.DISABLED)
        self.chat_text.grid(row=0, column=0, sticky="nsew")
        scr = tk.Scrollbar(chat_outer, command=self.chat_text.yview)
        scr.grid(row=0, column=1, sticky="ns")
        self.chat_text.configure(yscrollcommand=scr.set)
##
        entry_frame = tk.Frame(chat_outer)
        entry_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        entry_frame.columnconfigure(0, weight=1)

        self.msg_entry = tk.Entry(entry_frame)
        self.msg_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda _e: self.send_message())

        send_btn = tk.Button(entry_frame, text="Wyślij", width=10, command=self.send_message)
        send_btn.grid(row=0, column=1)
##
        vc.on_call_started          = self.on_call_started
        vc.on_call_ended            = self.on_call_ended
        vc.on_incoming_call_request = self.gui_incoming_call
        vc.on_new_fpr               = self.gui_new_fpr
        vc.on_contact_saved         = lambda *_: self.refresh_contacts()
        vc.on_request_contact_name = self.gui_contact_naming
        vc.on_text_message = self.gui_on_text_message

    def delete_selected_contact(self):
        sel = self.contacts_listbox.curselection()
        if not sel:
            messagebox.showwarning("Usuń kontakt", "Wybierz kontakt z listy.")
            return
        index = sel[0]
        name, ip, _ = self.contacts[index]

        if not messagebox.askyesno(
                "Potwierdzenie",
                f"Czy na pewno usunąć kontakt „{name}” ({ip}) oraz całą jego konwersację?"
        ):
            return

        ok = vc.delete_contact(ip)  # usuwa też historię
        if not ok:
            messagebox.showerror("Błąd", "Nie udało się usunąć kontaktu.")
            return

        # odśwież listę i wyczyść widok czatu, jeśli patrzyliśmy na ten kontakt
        self.refresh_contacts()
        if self.current_chat_ip == ip:
            self.current_chat_ip = None
            self.chat_text.config(state=tk.NORMAL)
            self.chat_text.delete("1.0", tk.END)
            self.chat_text.insert(tk.END, "Brak wiadomości.")
            self.chat_text.config(state=tk.DISABLED)

    def _update_online_button(self, online: bool):
        if online:
            self.toggle_listen_button.config(text="online", bg="#2ecc71", activebackground="#27ae60", fg="white")
        else:
            self.toggle_listen_button.config(text="offline", bg="#e74c3c", activebackground="#c0392b", fg="white")


    def init_chat_for_selected(self):
        sel = self.contacts_listbox.curselection()
        if not sel:
            return
        _, ip, _ = self.contacts[sel[0]]
        vc.send_chat_hello(ip)
        messagebox.showinfo("Czat", f"Wysłano HELLO do {ip}")

    def gui_on_text_message(self, ip, ts, text, incoming):
        if ip != self.current_chat_ip:
            return
        who = "Ty" if not incoming else self._name_for_ip(ip)
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, f"[{ts}] {who}: {text}\n")
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)

    def _name_for_ip(self, ip: str) -> str:
        for name, saved_ip, _ in self.contacts:
            if saved_ip == ip:
                return name
        return ip

    def gui_contact_naming(self, ip, rsa_bytes, save_cb):
        def _ask():
            name = simpledialog.askstring(
                "Nazwa kontaktu",
                f"Podaj nazwę dla nowego kontaktu {ip}:")
            if name:
                save_cb(name)
                self.refresh_contacts()
        self.root.after(0, _ask)

    def call_selected_contact(self):
        if vc.is_call_active():
            messagebox.showwarning("Trwa rozmowa", "Najpierw zakończ bieżące połączenie.")
            return
        sel = self.contacts_listbox.curselection()
        if not sel:
            messagebox.showwarning("Brak wyboru", "Wybierz kontakt z listy.")
            return
        index = sel[0]
        _, ip, _ = self.contacts[index]
        threading.Thread(target=vc.initiate_call, args=(ip,), daemon=True).start()

    def send_message(self):
        text = self.msg_entry.get().strip()
        if not text or not self.current_chat_ip:
            return

        # >>> NOWE ZASADY:
        # 1) My musimy być online
        if not vc.is_online():
            messagebox.showwarning("Czat", "Jesteś offline. Włącz tryb online, aby wysłać wiadomość.")
            return

        # 2) Automatyczny handshake przy wysyłaniu (bez klikania)
        if not vc.ensure_chat_ready(self.current_chat_ip, timeout=2.0):
            messagebox.showinfo("Czat", "Nie udało się nawiązać szyfrowanego kanału (druga osoba prawdopodobnie offline). "
                                        "Wiadomość nie została wysłana ani zapisana.")
            return

        # 3) Wysłanie (zabezpieczenie: nie zapisujemy, jeśli wysyłka zablokowana)
        ok = vc.send_text_message(self.current_chat_ip, text)
        if not ok:
            messagebox.showinfo("Czat", "Nie udało się wysłać (brak klucza lub offline). "
                                        "Wiadomość nie została zapisana.")
            return

        self.msg_entry.delete(0, tk.END)

    def open_contact_window(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Nawiąż kontakt")

        tk.Label(dialog, text="IP kontaktu:").pack(pady=5)
        ip_entry = tk.Entry(dialog)
        ip_entry.pack()

        tk.Label(dialog, text="Nazwa kontaktu:").pack(pady=5)
        name_entry = tk.Entry(dialog)
        name_entry.pack()

        def send_fpr():
            ip = ip_entry.get().strip()
            name = name_entry.get().strip()
            if not ip or not name:
                messagebox.showerror("Błąd", "Wprowadź dane.")
                return
            # NOWE: jedna funkcja, która i wyśle FPR, i zapamięta nazwę
            vc.initiate_contact(ip, name)
            messagebox.showinfo("Wysłano", f"Wysłano fingerprint do {ip}")
            dialog.destroy()

        tk.Button(dialog, text="Wyślij", command=send_fpr).pack(pady=10)

    def toggle_listener(self):
        if self.listening:
            self.listening = False
            vc.stop_listener()
            self._update_online_button(False)
        else:
            self.listening = True
            vc.start_listener()
            self._update_online_button(True)

    #  wczytanie czatu
    def on_contact_select(self, _event):
        sel = self.contacts_listbox.curselection()
        if not sel:
            return
        index = sel[0]
        _, ip, _ = self.contacts[index]
        self.load_chat(ip)

    def load_chat(self, ip: str):
        self.current_chat_ip = ip
        filename = f"messages_{ip}.txt"
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete("1.0", tk.END)

        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split("|", 2)
                    if len(parts) < 3:
                        continue
                    who, ts, msg = parts
                    if who == "ME":
                        prefix = "Ty"
                    else:
                        prefix = self._name_for_ip(ip)  # <<< ZMIANA: nazwa zamiast IP
                    self.chat_text.insert(tk.END, f"[{ts}] {prefix}: {msg}\n")
        else:
            self.chat_text.insert(tk.END, "Brak wiadomości.")

        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)

    def gui_incoming_call(self, ip, fingerprint, accept_cb, reject_cb):
        def _ask():
            msg = f"Odebrać połączenie od {ip}?"
            if fingerprint:
                msg = (f"Nieznany rozmówca {ip}\nFingerprint: {fingerprint}\n\nZaakceptować połączenie?")
            if messagebox.askyesno("Połączenie przychodzące", msg):
                accept_cb()
            else:
                reject_cb()
        self.root.after(0, _ask)

    def gui_new_fpr(self, ip, fingerprint, accept_cb):
        def _ask():
            if messagebox.askyesno("Nowy fingerprint", f"Otrzymano fingerprint od {ip}:\n{fingerprint}\nZaakceptować?"):
                accept_cb()
        self.root.after(0, _ask)

    def open_call_window(self, peer_name, peer_ip):
        call_win = tk.Toplevel(self.root)
        call_win.title("Rozmowa")

        tk.Label(call_win, text=f"Rozmowa z: {peer_name} ({peer_ip})", font=("Arial", 14)).pack(padx=20, pady=(20, 10))
        tk.Button(call_win, text="Rozłącz", font=("Arial", 12), command=vc.end_call).pack(pady=(0, 20))
        call_win.protocol("WM_DELETE_WINDOW", vc.end_call)
        self._current_call_window = call_win

    def on_call_started(self, ip):
        def _gui():
            self.refresh_contacts()
            name = next((n for n, saved_ip, _ in self.contacts if saved_ip == ip), ip)
            self.open_call_window(name, ip)
        self.root.after(0, _gui)

    def on_call_ended(self, _ip):
        def _close():
            if hasattr(self, "_current_call_window") and self._current_call_window:
                self._current_call_window.destroy()
                self._current_call_window = None
        self.root.after(0, _close)

    def refresh_contacts(self):
        self.contacts = vc.load_contacts()
        self.contacts_listbox.delete(0, tk.END)
        for name, ip, _ in self.contacts:
            display = f"{name} ({ip})"
            self.contacts_listbox.insert(tk.END, display)

if __name__ == "__main__":
    root = tk.Tk()
    app = VoiceApp(root)
    root.mainloop()