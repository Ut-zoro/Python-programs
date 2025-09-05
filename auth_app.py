import json, os, hashlib, secrets, tkinter as tk
from tkinter import messagebox, ttk

USERS_DB = "users.json"

# ---------- tiny local "db" helpers ----------
def load_users():
    if not os.path.exists(USERS_DB):
        return {}
    try:
        with open(USERS_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users):
    with open(USERS_DB, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def create_user(username: str, password: str) -> None:
    users = load_users()
    if username in users:
        raise ValueError("Username already exists.")
    if len(username.strip()) < 3:
        raise ValueError("Username must be at least 3 characters.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")
    salt = secrets.token_hex(16)
    users[username] = {"salt": salt, "hash": hash_password(password, salt)}
    save_users(users)

def verify_user(username: str, password: str) -> bool:
    users = load_users()
    record = users.get(username)
    if not record:
        return False
    return hash_password(password, record["salt"]) == record["hash"]

# ---------- UI ----------
class AuthApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sign in")
        self.geometry("360x420")
        self.minsize(360, 420)
        self.configure(bg="#f6f7fb")
        self._center()

        # root container
        card = tk.Frame(self, bg="white", bd=0, highlightthickness=0)
        card.place(relx=0.5, rely=0.5, anchor="c", width=320, height=340)

        # subtle shadow effect
        card_shadow = tk.Frame(self, bg="#e6e8ef")
        card_shadow.place(relx=0.5, rely=0.5, anchor="c", width=322, height=342)
        card.lift()

        # header
        title = tk.Label(card, text="Welcome back", bg="white", fg="#0f172a",
                         font=("Segoe UI", 16, "bold"))
        subtitle = tk.Label(card, text="Sign in to continue", bg="white", fg="#475569",
                            font=("Segoe UI", 10))
        title.pack(pady=(20, 2))
        subtitle.pack(pady=(0, 14))

        # form
        frm = tk.Frame(card, bg="white")
        frm.pack(fill="x", padx=20)

        self.var_user = tk.StringVar()
        self.var_pass = tk.StringVar()
        self.var_show = tk.BooleanVar(value=False)

        # username
        lbl_user = tk.Label(frm, text="Username", bg="white", fg="#334155", font=("Segoe UI", 9))
        ent_user = ttk.Entry(frm, textvariable=self.var_user, font=("Segoe UI", 10))
        lbl_user.pack(anchor="w")
        ent_user.pack(fill="x", ipady=6, pady=(2, 12))

        # password with show/hide
        lbl_pass = tk.Label(frm, text="Password", bg="white", fg="#334155", font=("Segoe UI", 9))
        self.ent_pass = ttk.Entry(frm, textvariable=self.var_pass, show="•", font=("Segoe UI", 10))
        lbl_pass.pack(anchor="w")
        self.ent_pass.pack(fill="x", ipady=6, pady=(2, 6))

        chk = ttk.Checkbutton(frm, text="Show password", variable=self.var_show,
                              command=self._toggle_pw)
        chk.pack(anchor="w")

        # feedback
        self.lbl_msg = tk.Label(card, text="", bg="white", fg="#dc2626", font=("Segoe UI", 9))
        self.lbl_msg.pack(pady=(8, 0))

        # buttons
        btn_signin = ttk.Button(card, text="Sign in", command=self._signin)
        btn_signin.pack(fill="x", padx=20, pady=(16, 6))

        sep = ttk.Separator(card, orient="horizontal")
        sep.pack(fill="x", padx=20, pady=(6, 6))

        btn_create = ttk.Button(card, text="Create new account", command=self._open_signup)
        btn_create.pack(fill="x", padx=20)

        # style polish
        style = ttk.Style(self)
        try:
            self.call("tk", "scaling", 1.2)
        except Exception:
            pass
        style.configure("TButton", padding=8)
        style.configure("TEntry")
        style.configure("TCheckbutton", padding=4)

        # keyboard UX
        ent_user.focus()
        self.bind("<Return>", lambda e: self._signin())

    def _center(self):
        self.update_idletasks()
        w = self.winfo_width() or 360
        h = self.winfo_height() or 420
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 3
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _toggle_pw(self):
        self.ent_pass.config(show="" if self.var_show.get() else "•")

    def _signin(self):
        user = self.var_user.get().strip()
        pw = self.var_pass.get()
        if not user or not pw:
            self._set_msg("Please fill in both fields.")
            return

        if verify_user(user, pw):
            self._set_msg("", ok=True)
            messagebox.showinfo("Success", f"Welcome, {user}!")
            self._go_to_app()
        else:
            self._set_msg("Invalid username or password.")

    def _set_msg(self, text, ok=False):
        self.lbl_msg.config(text=text, fg="#16a34a" if ok else "#dc2626")

    def _open_signup(self):
        SignupDialog(self)

    def _go_to_app(self):
        # Replace this with your main app window.
        top = tk.Toplevel(self)
        top.title("Your App")
        top.geometry("400x200")
        tk.Label(top, text="You are signed in ✔", font=("Segoe UI", 12, "bold")).pack(pady=30)
        ttk.Button(top, text="Close", command=top.destroy).pack()

class SignupDialog(tk.Toplevel):
    def __init__(self, master: AuthApp):
        super().__init__(master)
        self.title("Create account")
        self.transient(master)
        self.grab_set()
        self.configure(bg="white")
        self.geometry("340x300")
        self._build()

    def _build(self):
        tk.Label(self, text="Create a new account", bg="white",
                 fg="#0f172a", font=("Segoe UI", 14, "bold")).pack(pady=(16, 12))

        frm = tk.Frame(self, bg="white"); frm.pack(fill="x", padx=20)

        self.var_user = tk.StringVar()
        self.var_pw1 = tk.StringVar()
        self.var_pw2 = tk.StringVar()

        tk.Label(frm, text="Username", bg="white", fg="#334155", font=("Segoe UI", 9)).pack(anchor="w")
        self.ent_user = ttk.Entry(frm, textvariable=self.var_user, font=("Segoe UI", 10))
        self.ent_user.pack(fill="x", ipady=6, pady=(2, 10))

        tk.Label(frm, text="Password", bg="white", fg="#334155", font=("Segoe UI", 9)).pack(anchor="w")
        self.ent_pw1 = ttk.Entry(frm, textvariable=self.var_pw1, show="•", font=("Segoe UI", 10))
        self.ent_pw1.pack(fill="x", ipady=6, pady=(2, 10))

        tk.Label(frm, text="Confirm password", bg="white", fg="#334155", font=("Segoe UI", 9)).pack(anchor="w")
        self.ent_pw2 = ttk.Entry(frm, textvariable=self.var_pw2, show="•", font=("Segoe UI", 10))
        self.ent_pw2.pack(fill="x", ipady=6, pady=(2, 10))

        self.lbl_msg = tk.Label(self, text="", bg="white", fg="#dc2626", font=("Segoe UI", 9))
        self.lbl_msg.pack()

        btns = tk.Frame(self, bg="white"); btns.pack(fill="x", padx=20, pady=(12, 12))
        ttk.Button(btns, text="Create account", command=self._create).pack(side="left", expand=True, fill="x")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left", expand=True, fill="x", padx=(8,0))

        self.ent_user.focus()
        self.bind("<Return>", lambda e: self._create())

    def _create(self):
        u = self.var_user.get().strip()
        p1 = self.var_pw1.get()
        p2 = self.var_pw2.get()

        if not u or not p1 or not p2:
            self._set_msg("Please complete all fields."); return
        if p1 != p2:
            self._set_msg("Passwords do not match."); return
        try:
            create_user(u, p1)
            messagebox.showinfo("Account created", "You can sign in now.")
            self.destroy()
        except ValueError as e:
            self._set_msg(str(e))

    def _set_msg(self, text):
        self.lbl_msg.config(text=text)

if __name__ == "__main__":
    # Optional: create a demo user on first run for quick testing
    users = load_users()
    if "demo" not in users:
        try:
            create_user("demo", "demo123")
        except Exception:
            pass
    app = AuthApp()
    app.mainloop()
