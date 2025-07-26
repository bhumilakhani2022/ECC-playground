# Main GUI for ECC Playground
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ecc_math import scalar_mult, is_on_curve
from curves import get_preset_curves, make_custom_curve
from visualizer import plot_curve_and_points, embed_plot_in_tk
from export_utils import export_to_json, export_to_text

class ECCPlaygroundApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ECC Playground – Visual Cryptographic Simulator")
        self.geometry("900x700")
        self.curves = get_preset_curves()
        self.selected_curve = None
        self.custom_curve_params = {'a': tk.StringVar(), 'b': tk.StringVar(), 'p': tk.StringVar(), 'gx': tk.StringVar(), 'gy': tk.StringVar(), 'n': tk.StringVar()}
        self.scalar = tk.StringVar()
        self.result_point = None
        self.steps = []
        self.current_step = 0
        self._build_ui()

    def _build_ui(self):
        # Top frame for curve selection and parameters
        top = ttk.Frame(self)
        top.pack(side='top', fill='x', padx=10, pady=5)
        ttk.Label(top, text="Curve:").pack(side='left')
        self.curve_var = tk.StringVar(value=list(self.curves.keys())[0])
        curve_menu = ttk.OptionMenu(top, self.curve_var, self.curve_var.get(), *self.curves.keys(), command=self._on_curve_select)
        curve_menu.pack(side='left')
        self.custom_frame = ttk.Frame(top)
        # Custom curve fields (hidden by default)
        for label, var in zip(['a', 'b', 'p', 'Gx', 'Gy', 'n'], self.custom_curve_params.values()):
            ttk.Label(self.custom_frame, text=label+':').pack(side='left')
            ttk.Entry(self.custom_frame, textvariable=var, width=6).pack(side='left')
        # Scalar input
        ttk.Label(top, text="  Scalar k:").pack(side='left')
        ttk.Entry(top, textvariable=self.scalar, width=8).pack(side='left')
        ttk.Button(top, text="Compute", command=self._on_compute).pack(side='left', padx=5)
        # Step controls
        step_frame = ttk.Frame(self)
        step_frame.pack(side='top', fill='x', padx=10, pady=5)
        ttk.Button(step_frame, text="Step", command=self._on_step).pack(side='left')
        ttk.Button(step_frame, text="Auto-play", command=self._on_autoplay).pack(side='left')
        ttk.Button(step_frame, text="Reset", command=self._on_reset).pack(side='left')
        ttk.Button(step_frame, text="Export JSON", command=self._on_export_json).pack(side='left')
        ttk.Button(step_frame, text="Export Text", command=self._on_export_text).pack(side='left')
        # Math explanation
        self.explanation = tk.Text(self, height=4, font=('Consolas', 11))
        self.explanation.pack(side='bottom', fill='x', padx=10, pady=5)
        # Plot area
        self.plot_canvas = tk.Frame(self, bg='white', height=500)
        self.plot_canvas.pack(side='top', fill='both', expand=1, padx=10, pady=5)
        self._on_curve_select(self.curve_var.get())

    def _on_curve_select(self, value):
        if value == 'Custom':
            self.custom_frame.pack(side='left')
        else:
            self.custom_frame.pack_forget()
        self.selected_curve = self.curves.get(value)
        self._draw_curve()

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
            # Compute with steps
            self.result_point, steps = scalar_mult(k, G, curve['a'], curve['p'], return_steps=True)
            self.steps = []
            
            # Process steps with previous points for visualization
            for step in steps:
                if len(step) == 4:  # New format with previous point
                    step_num, op_type, current, previous = step
                    if op_type == "double":
                        self.steps.append((current, previous, f"Step {step_num}: Double point {previous} → {current}"))
                    else:
                        self.steps.append((current, previous, f"Step {step_num}: Add G to {previous} → {current}"))
                else:  # Initial point
                    _, op_type, point = step
                    self.steps.append((point, None, f"Start at base point G = {point}"))
                    
            self.current_step = 0
            self._draw_curve()
            self._show_explanation()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _on_step(self):
        if not self.steps:
            return
        self.current_step = (self.current_step + 1) % len(self.steps)
        self._draw_curve()
        self._show_explanation()
            return
        self.current_step = min(self.current_step + 1, len(self.steps) - 1)
        self._draw_curve()
        self._show_explanation()

    def _on_autoplay(self):
        # Placeholder: In a real app, animate through steps
        for _ in range(len(self.steps) - self.current_step - 1):
            self._on_step()
            self.update()
            self.after(500)

    def _on_reset(self):
        self.current_step = 0
        self._draw_curve()
        self._show_explanation()

    def _on_export_json(self):
        if not self.result_point:
            return
        filename = filedialog.asksaveasfilename(defaultextension='.json')
        if filename:
            export_to_json({'result': self.result_point}, filename)

    def _on_export_text(self):
        if not self.result_point:
            return
        filename = filedialog.asksaveasfilename(defaultextension='.txt')
        if filename:
            export_to_text({'result': self.result_point}, filename)

    def _draw_curve(self):
        if not self.selected_curve:
            return
        curve = self._get_curve()
        if not curve:
            return
        
        # Get all points on curve for reference
        points = []
        for x in range(curve['p']):
            for y in range(curve['p']):
                if is_on_curve((x, y), curve['a'], curve['b'], curve['p']):
                    points.append((x, y))
                    
        # Get current point and previous point for highlighting
        highlight = None
        prev_point = None
        if self.steps and 0 <= self.current_step < len(self.steps):
            step = self.steps[self.current_step]
            highlight = step[0]  # Current point
            prev_point = step[1]  # Previous point if available
            
        # Update plot
        fig, ax = plot_curve_and_points(curve, points, highlight=highlight, prev_point=prev_point)
        self.plot_widget = embed_plot_in_tk(self.plot_canvas, fig)
        
        # Update explanation
        if self.steps and 0 <= self.current_step < len(self.steps):
            self._show_explanation(self.steps[self.current_step][2])
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

if __name__ == '__main__':
    app = ECCPlaygroundApp()
    app.mainloop()