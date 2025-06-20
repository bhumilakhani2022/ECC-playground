# Main GUI for ECC Playground
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ecc_math import scalar_mult, is_on_curve, get_public_key, ecdh_shared_secret, ecdsa_sign, ecdsa_verify
from curves import get_preset_curves, make_custom_curve
from visualizer import plot_curve_and_points, embed_plot_in_tk
from export_utils import export_to_json, export_to_text

class ECCPlaygroundApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ECC Playground – Visual Cryptographic Simulator")
        self.geometry("1200x800")
        self.configure(bg='#f4f4f4')
        self.curves = get_preset_curves()
        self.selected_curve = None
        self.custom_curve_params = {'a': tk.StringVar(), 'b': tk.StringVar(), 'p': tk.StringVar(), 'gx': tk.StringVar(), 'gy': tk.StringVar(), 'n': tk.StringVar()}
        self.scalar = tk.StringVar()
        self.result_point = None
        self.steps = []
        self.current_step = 0
        self.status_var = tk.StringVar(value="Welcome to ECC Playground!")
        self.history = []
        self._setup_style()
        self._build_ui()

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TButton', font=('Segoe UI', 12), padding=8)
        style.configure('TLabel', font=('Segoe UI', 12))
        style.configure('TEntry', font=('Segoe UI', 12), padding=4)
        style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), background='#2d6cdf', foreground='white')
        style.configure('Sidebar.TFrame', background='#e6eaff')
        style.configure('Main.TFrame', background='#f4f4f4')

    def _build_ui(self):
        # Header
        header = ttk.Label(self, text="ECC Playground – Visual Cryptographic Simulator", style='Header.TLabel', anchor='center')
        header.pack(side='top', fill='x')

        # Main frame with sidebar and content
        main_frame = ttk.Frame(self, style='Main.TFrame')
        main_frame.pack(side='top', fill='both', expand=1)

        # Sidebar for curve info and history
        sidebar = ttk.Frame(main_frame, width=300, style='Sidebar.TFrame')
        sidebar.pack(side='left', fill='y', padx=(0,10), pady=10)
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="Curve Info", font=('Segoe UI', 14, 'bold'), background='#e6eaff').pack(pady=(10,5))
        self.curve_info = tk.Text(sidebar, height=10, width=32, font=('Consolas', 11), bg='#f8faff', relief='flat')
        self.curve_info.pack(pady=5, padx=10)
        ttk.Label(sidebar, text="Computation History", font=('Segoe UI', 14, 'bold'), background='#e6eaff').pack(pady=(20,5))
        self.history_box = tk.Listbox(sidebar, height=10, font=('Consolas', 11), bg='#f8faff', relief='flat')
        self.history_box.pack(pady=5, padx=10, fill='x')
        # Placeholder for more columns/sections
        ttk.Label(sidebar, text="[More Features Coming Soon]", background='#e6eaff', foreground='#888').pack(pady=(30,5))

        # Content frame (main area)
        content = ttk.Frame(main_frame, style='Main.TFrame')
        content.pack(side='left', fill='both', expand=1, pady=10)

        # Top controls
        controls = ttk.Frame(content)
        controls.pack(side='top', fill='x', padx=10, pady=10)
        ttk.Label(controls, text="Curve:").pack(side='left', padx=5)
        self.curve_var = tk.StringVar(value=list(self.curves.keys())[0])
        curve_menu = ttk.OptionMenu(controls, self.curve_var, self.curve_var.get(), *self.curves.keys(), command=self._on_curve_select)
        curve_menu.config(width=15)
        curve_menu.pack(side='left', padx=5)
        self.custom_frame = ttk.Frame(controls)
        for label, var in zip(['a', 'b', 'p', 'Gx', 'Gy', 'n'], self.custom_curve_params.values()):
            ttk.Label(self.custom_frame, text=label+':').pack(side='left', padx=2)
            ttk.Entry(self.custom_frame, textvariable=var, width=8).pack(side='left', padx=2)
        ttk.Label(controls, text="  Scalar k:").pack(side='left', padx=5)
        ttk.Entry(controls, textvariable=self.scalar, width=10).pack(side='left', padx=5)
        ttk.Button(controls, text="Compute", command=self._on_compute).pack(side='left', padx=8)
        # Step controls
        ttk.Button(controls, text="Step", command=self._on_step).pack(side='left', padx=5)
        ttk.Button(controls, text="Auto-play", command=self._on_autoplay).pack(side='left', padx=5)
        ttk.Button(controls, text="Reset", command=self._on_reset).pack(side='left', padx=5)
        ttk.Button(controls, text="Export JSON", command=self._on_export_json).pack(side='left', padx=5)
        ttk.Button(controls, text="Export Text", command=self._on_export_text).pack(side='left', padx=5)

        # Plot area
        self.plot_canvas = tk.Frame(content, bg='white', height=500)
        self.plot_canvas.pack(side='top', fill='both', expand=1, padx=10, pady=10)

        # Math explanation
        ttk.Label(content, text="Explanation:", font=('Segoe UI', 13, 'bold')).pack(side='top', anchor='w', padx=10, pady=(10,0))
        self.explanation = tk.Text(content, height=4, font=('Consolas', 12), bg='#f8faff', relief='flat')
        self.explanation.pack(side='top', fill='x', padx=10, pady=5)

        # Status bar
        status_bar = ttk.Label(self, textvariable=self.status_var, anchor='w', background='#2d6cdf', foreground='white', font=('Segoe UI', 11))
        status_bar.pack(side='bottom', fill='x')

        # --- ECDH Section ---
        ecdh_frame = ttk.LabelFrame(content, text="ECDH Key Exchange", padding=10)
        ecdh_frame.pack(side='top', fill='x', padx=10, pady=10)
        ttk.Label(ecdh_frame, text="Alice Private Key:").grid(row=0, column=0, sticky='e')
        self.ecdh_alice_priv = tk.StringVar()
        ttk.Entry(ecdh_frame, textvariable=self.ecdh_alice_priv, width=12).grid(row=0, column=1)
        ttk.Label(ecdh_frame, text="Bob Private Key:").grid(row=0, column=2, sticky='e')
        self.ecdh_bob_priv = tk.StringVar()
        ttk.Entry(ecdh_frame, textvariable=self.ecdh_bob_priv, width=12).grid(row=0, column=3)
        ttk.Button(ecdh_frame, text="Compute Shared Secret", command=self._on_ecdh_compute).grid(row=0, column=4, padx=8)
        self.ecdh_result = tk.Text(ecdh_frame, height=4, width=80, font=('Consolas', 11), bg='#f8faff', relief='flat')
        self.ecdh_result.grid(row=1, column=0, columnspan=5, pady=5)

        # --- ECDSA Section ---
        ecdsa_frame = ttk.LabelFrame(content, text="ECDSA Digital Signature", padding=10)
        ecdsa_frame.pack(side='top', fill='x', padx=10, pady=10)
        # Sign
        ttk.Label(ecdsa_frame, text="Message to Sign:").grid(row=0, column=0, sticky='e')
        self.ecdsa_msg = tk.StringVar()
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_msg, width=30).grid(row=0, column=1)
        ttk.Label(ecdsa_frame, text="Private Key:").grid(row=0, column=2, sticky='e')
        self.ecdsa_priv = tk.StringVar()
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_priv, width=12).grid(row=0, column=3)
        ttk.Button(ecdsa_frame, text="Sign Message", command=self._on_ecdsa_sign).grid(row=0, column=4, padx=8)
        self.ecdsa_sign_result = tk.Text(ecdsa_frame, height=2, width=80, font=('Consolas', 11), bg='#f8faff', relief='flat')
        self.ecdsa_sign_result.grid(row=1, column=0, columnspan=5, pady=5)
        # Verify
        ttk.Label(ecdsa_frame, text="Message to Verify:").grid(row=2, column=0, sticky='e')
        self.ecdsa_verify_msg = tk.StringVar()
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_verify_msg, width=30).grid(row=2, column=1)
        ttk.Label(ecdsa_frame, text="Signature r:").grid(row=2, column=2, sticky='e')
        self.ecdsa_sig_r = tk.StringVar()
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_sig_r, width=12).grid(row=2, column=3)
        ttk.Label(ecdsa_frame, text="Signature s:").grid(row=3, column=2, sticky='e')
        self.ecdsa_sig_s = tk.StringVar()
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_sig_s, width=12).grid(row=3, column=3)
        ttk.Label(ecdsa_frame, text="Public Key x:").grid(row=2, column=4, sticky='e')
        self.ecdsa_pub_x = tk.StringVar()
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_pub_x, width=18).grid(row=2, column=5)
        ttk.Label(ecdsa_frame, text="Public Key y:").grid(row=3, column=4, sticky='e')
        self.ecdsa_pub_y = tk.StringVar()
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_pub_y, width=18).grid(row=3, column=5)
        ttk.Button(ecdsa_frame, text="Verify Signature", command=self._on_ecdsa_verify).grid(row=2, column=6, rowspan=2, padx=8)
        self.ecdsa_verify_result = tk.Text(ecdsa_frame, height=2, width=80, font=('Consolas', 11), bg='#f8faff', relief='flat')
        self.ecdsa_verify_result.grid(row=4, column=0, columnspan=7, pady=5)

        self._on_curve_select(self.curve_var.get())

    def _on_curve_select(self, value):
        if value == 'Custom':
            self.custom_frame.pack(side='left', padx=5)
        else:
            self.custom_frame.pack_forget()
        self.selected_curve = self.curves.get(value)
        self._update_curve_info()
        self._draw_curve()

    def _update_curve_info(self):
        curve = self._get_curve()
        if not curve:
            self.curve_info.delete('1.0', tk.END)
            return
        info = f"a: {curve['a']}\nb: {curve['b']}\np: {curve['p']}\nG: {curve['G']}\nn: {curve['n']}"
        self.curve_info.delete('1.0', tk.END)
        self.curve_info.insert(tk.END, info)

    def _get_curve(self):
        if self.curve_var.get() == 'Custom':
            try:
                a = int(self.custom_curve_params['a'].get())
                b = int(self.custom_curve_params['b'].get())
                p = int(self.custom_curve_params['p'].get())
                gx = int(self.custom_curve_params['gx'].get())
                gy = int(self.custom_curve_params['gy'].get())
                n = int(self.custom_curve_params['n'].get())
                return make_custom_curve(a, b, p, (gx, gy), n)
            except Exception:
                messagebox.showerror("Invalid Input", "Please enter valid integers for custom curve.")
                return None
        return self.selected_curve

    def _on_compute(self):
        curve = self._get_curve()
        if not curve:
            return
        try:
            k = int(self.scalar.get())
            G = curve['G']
            if not is_on_curve(G, curve['a'], curve['b'], curve['p']):
                messagebox.showerror("Invalid Base Point", "Base point is not on the curve.")
                return
            self.result_point, step_data = scalar_mult(k, G, curve['a'], curve['p'], return_steps=True)
            self.steps = [(G, f"Start at G = {G}")] + step_data
            self.current_step = 0
            self.history.append(f"k={k}: {self.result_point}")
            self.history_box.insert(tk.END, f"k={k}: {self.result_point}")
            self.status_var.set(f"Computed {k}*G = {self.result_point}")
            self._draw_curve()
            self._show_explanation()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set(f"Error: {e}")

    def _on_step(self):
        if not self.steps:
            return
        self.current_step = min(self.current_step + 1, len(self.steps) - 1)
        self._draw_curve()
        self._show_explanation()

    def _on_autoplay(self):
        for _ in range(len(self.steps) - self.current_step - 1):
            self._on_step()
            self.update()
            self.after(500)

    def _on_reset(self):
        self.current_step = 0
        self._draw_curve()
        self._show_explanation()
        self.status_var.set("Reset to initial state.")

    def _on_export_json(self):
        if not self.result_point:
            return
        filename = filedialog.asksaveasfilename(defaultextension='.json')
        if filename:
            export_to_json({'result': self.result_point}, filename)
            self.status_var.set(f"Exported result to {filename}")

    def _on_export_text(self):
        if not self.result_point:
            return
        filename = filedialog.asksaveasfilename(defaultextension='.txt')
        if filename:
            export_to_text({'result': self.result_point}, filename)
            self.status_var.set(f"Exported result to {filename}")

    def _draw_curve(self):
        curve = self._get_curve()
        if not curve:
            return
        points = [pt for pt, _ in self.steps[:self.current_step+1]] if self.steps else []
        highlight = points[-1] if points else None
        fig, ax = plot_curve_and_points(curve, points=points, highlight=highlight)
        embed_plot_in_tk(self.plot_canvas, fig)

    def _show_explanation(self):
        if not self.steps:
            self.explanation.delete('1.0', tk.END)
            return
        _, expl = self.steps[self.current_step]
        self.explanation.delete('1.0', tk.END)
        self.explanation.insert(tk.END, expl)

    def _on_ecdh_compute(self):
        curve = self._get_curve()
        if not curve:
            return
        try:
            a_priv = int(self.ecdh_alice_priv.get())
            b_priv = int(self.ecdh_bob_priv.get())
            G = curve['G']
            a_pub = get_public_key(a_priv, G, curve['a'], curve['p'])
            b_pub = get_public_key(b_priv, G, curve['a'], curve['p'])
            shared1 = ecdh_shared_secret(a_priv, b_pub, curve['a'], curve['p'])
            shared2 = ecdh_shared_secret(b_priv, a_pub, curve['a'], curve['p'])
            result = f"Alice Public: {a_pub}\nBob Public: {b_pub}\nShared Secret (Alice): {shared1}\nShared Secret (Bob): {shared2}\nMatch: {shared1 == shared2}"
            self.ecdh_result.delete('1.0', tk.END)
            self.ecdh_result.insert(tk.END, result)
            self.status_var.set("ECDH computed.")
        except Exception as e:
            self.ecdh_result.delete('1.0', tk.END)
            self.ecdh_result.insert(tk.END, f"Error: {e}")
            self.status_var.set(f"ECDH error: {e}")

    def _on_ecdsa_sign(self):
        curve = self._get_curve()
        if not curve:
            return
        try:
            msg = self.ecdsa_msg.get().encode()
            priv = int(self.ecdsa_priv.get())
            G = curve['G']
            r, s = ecdsa_sign(msg, priv, G, curve['a'], curve['p'], curve['n'])
            self.ecdsa_sign_result.delete('1.0', tk.END)
            self.ecdsa_sign_result.insert(tk.END, f"Signature: (r={r}, s={s})")
            self.ecdsa_sig_r.set(str(r))
            self.ecdsa_sig_s.set(str(s))
            self.status_var.set("Message signed.")
        except Exception as e:
            self.ecdsa_sign_result.delete('1.0', tk.END)
            self.ecdsa_sign_result.insert(tk.END, f"Error: {e}")
            self.status_var.set(f"ECDSA sign error: {e}")

    def _on_ecdsa_verify(self):
        curve = self._get_curve()
        if not curve:
            return
        try:
            msg = self.ecdsa_verify_msg.get().encode()
            r = int(self.ecdsa_sig_r.get())
            s = int(self.ecdsa_sig_s.get())
            x = int(self.ecdsa_pub_x.get())
            y = int(self.ecdsa_pub_y.get())
            pub = (x, y)
            G = curve['G']
            valid = ecdsa_verify(msg, (r, s), pub, G, curve['a'], curve['p'], curve['n'])
            self.ecdsa_verify_result.delete('1.0', tk.END)
            self.ecdsa_verify_result.insert(tk.END, f"Signature valid: {valid}")
            self.status_var.set("ECDSA verification complete.")
        except Exception as e:
            self.ecdsa_verify_result.delete('1.0', tk.END)
            self.ecdsa_verify_result.insert(tk.END, f"Error: {e}")
            self.status_var.set(f"ECDSA verify error: {e}")

if __name__ == '__main__':
    app = ECCPlaygroundApp()
    app.mainloop()