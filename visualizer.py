# Visualizer for ECC using matplotlib

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import math

def plot_curve_and_points(curve, points=None, highlight=None, ax=None, labels=None, tangent_point=None, slope=None):
    """
    Plot the elliptic curve and given points.
    curve: dict with keys 'a', 'b', 'p'
    points: list of (x, y) tuples
    highlight: (x, y) tuple to highlight
    labels: list of str, labels for each point
    tangent_point: (x, y) tuple, point at which to draw tangent (optional)
    slope: float, slope of the tangent (optional)
    ax: matplotlib axis (optional)
    """
    a, b, p = curve['a'], curve['b'], curve['p']
    if ax is None:
        fig, ax = plt.subplots()
    else:
        fig = ax.figure
    ax.clear()
    valid_points = []
    valid_labels = []
    skipped = 0
    if points:
        for i, pt in enumerate(points):
            try:
                if (
                    pt is not None and
                    isinstance(pt, tuple) and
                    len(pt) == 2
                ):
                    x, y = int(pt[0]), int(pt[1])
                    valid_points.append((x, y))
                    if labels:
                        valid_labels.append(labels[i])
                else:
                    skipped += 1
            except Exception:
                skipped += 1
    # Plot smooth real curve as background for small p
    if p <= 1000:
        x_real = np.linspace(-p, p, 800)
        y_real_pos = []
        y_real_neg = []
        x_real_valid = []
        for x in x_real:
            rhs = x**3 + a*x + b
            if rhs >= 0:
                y = np.sqrt(rhs)
                x_real_valid.append(x)
                y_real_pos.append(y)
                y_real_neg.append(-y)
        ax.plot(x_real_valid, y_real_pos, color='green', linewidth=1.5, alpha=0.5, label='Real Curve')
        ax.plot(x_real_valid, y_real_neg, color='green', linewidth=1.5, alpha=0.5)
    # Plot curve points only if p is small
    if p <= 1000:
        x_vals = np.arange(0, p)
        y_curve = []
        x_curve = []
        for x in x_vals:
            rhs = (x ** 3 + a * x + b) % p
            for y in range(p):
                if (y * y) % p == rhs:
                    x_curve.append(x)
                    y_curve.append(y)
        ax.scatter(x_curve, y_curve, color='lightgray', s=10, label='Curve')
        title = f"y^2 = x^3 + {a}x + {b} (mod {p})"
    else:
        title = f"y^2 = x^3 + {a}x + {b} (mod {p})\n(Visualization only for p ≤ 1000)"
        ax.text(0.5, 0.5, "Curve not visualized for large p", fontsize=10, color='gray', ha='center', va='center', transform=ax.transAxes)
    # Plot points and labels
    if valid_points:
        xs, ys = zip(*valid_points)
        ax.scatter(xs, ys, color='blue', s=40, label='Points')
        if labels:
            for pt, label in zip(valid_points, valid_labels):
                if pt is not None:
                    ax.annotate(label, pt, textcoords="offset points", xytext=(0,10), ha='center', fontsize=9, color='blue')
    # Highlight current step
    if highlight and isinstance(highlight, tuple) and len(highlight) == 2:
        try:
            hx, hy = int(highlight[0]), int(highlight[1])
            ax.scatter([hx], [hy], color='red', s=80, label='Current')
            ax.annotate('Current', (hx, hy), textcoords="offset points", xytext=(0,-15), ha='center', fontsize=10, color='red')
        except Exception:
            pass
    # Draw tangent if provided (for small curves)
    if tangent_point is not None and slope is not None and p <= 1000:
        x0, y0 = tangent_point
        x_vals = np.linspace(x0-3, x0+3, 100)
        y_vals = slope * (x_vals - x0) + y0
        ax.plot(x_vals, y_vals, color='orange', linestyle='--', label='Tangent')
    ax.set_title(title)
    ax.set_xlabel('x')
    ax.set_ylabel('y')
    ax.legend()
    ax.grid(True)
    ax.set_aspect('equal', 'box')
    if p <= 1000 and 'x_curve' in locals() and x_curve:
        ax.set_xlim(-1, min(p, max(x_curve) + 2))
        ax.set_ylim(-1, min(p, max(y_curve) + 2))
    else:
        # For large p, auto-scale to points
        try:
            if valid_points:
                xs, ys = zip(*valid_points)
                # Only use finite numeric values
                xs = [float(x) for x in xs if isinstance(x, (int, float, np.integer, np.floating)) and np.isfinite(x)]
                ys = [float(y) for y in ys if isinstance(y, (int, float, np.integer, np.floating)) and np.isfinite(y)]
                if xs and ys and len(xs) > 0 and len(ys) > 0:
                    ax.set_xlim(min(xs)-1, max(xs)+1)
                    ax.set_ylim(min(ys)-1, max(ys)+1)
                else:
                    ax.set_xlim(-1, 10)
                    ax.set_ylim(-1, 10)
            else:
                ax.set_xlim(-1, 10)
                ax.set_ylim(-1, 10)
        except Exception as e:
            ax.set_xlim(-1, 10)
            ax.set_ylim(-1, 10)
    if skipped > 0:
        ax.text(0.5, 0.1, f"{skipped} point(s) skipped (invalid or at infinity)", fontsize=9, color='orange', ha='center', va='center', transform=ax.transAxes)
    return fig, ax

def embed_plot_in_tk(canvas, fig):
    """
    Embed a matplotlib figure in a Tkinter canvas.
    """
    for child in canvas.winfo_children():
        child.destroy()
    tkagg = FigureCanvasTkAgg(fig, master=canvas)
    tkagg.draw()
    tkagg.get_tk_widget().pack(fill='both', expand=1)
    return tkagg