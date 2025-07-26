# Visualizer for ECC using matplotlib

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def is_numeric_point(pt):
    return (
        isinstance(pt, (tuple, list)) and
        len(pt) == 2 and
        isinstance(pt[0], (int, float)) and
        isinstance(pt[1], (int, float))
    )

def plot_curve_and_points(curve, points=None, highlight=None, labels=None, ax=None, prev_point=None):
    """
    Plot the elliptic curve and given points.
    curve: dict with keys 'a', 'b', 'p'
    points: list of (x, y) tuples
    highlight: (x, y) tuple to highlight
    labels: list of labels for each point (optional)
    ax: matplotlib axis (optional)
    prev_point: previous point to show progression (optional)
    """
    a, b, p = curve['a'], curve['b'], curve['p']

    if ax is None:
        fig, ax = plt.subplots()
    else:
        fig = ax.figure

    ax.clear()

    # Plot the continuous curve only for small curves (toy curves)
    if p < 1000:  # Only show continuous curve for small prime fields
        try:
            x_continuous = np.linspace(-1, p + 1, 1000)
            y_real = []
            x_plot = []
            
            for x in x_continuous:
                try:
                    # Calculate the y values for the continuous curve
                    y = np.sqrt(complex(x**3 + a*x + b))
                    if abs(y.imag) < 1e-10:  # Only plot real points
                        y_real.extend([float(y.real), -float(y.real)])
                        x_plot.extend([x, x])
                except:
                    continue
                    
            if x_plot:  # Only plot if we have valid points
                ax.plot(x_plot, y_real, color='lightgray', alpha=0.5, label='Continuous Curve')
        except:
            pass  # Skip continuous curve if there's any error

    # Compute curve points over finite field
    x_curve, y_curve = [], []
    
    if p < 1000:
        # For small curves, compute all points
        for x in range(p):
            rhs = (x ** 3 + a * x + b) % p
            for y in range(p):
                if (y * y) % p == rhs:
                    x_curve.append(x)
                    y_curve.append(y)
    else:
        # For large curves, only compute points around our area of interest
        if points and len(points) > 0:
            # Get the range from our working points
            xs = [pt[0] for pt in points if is_numeric_point(pt)]
            if xs:
                x_min, x_max = min(xs), max(xs)
                x_range = x_max - x_min
                # Compute points in a window around our working points
                x_start = max(0, int(x_min - x_range * 0.5))
                x_end = min(p, int(x_max + x_range * 0.5))
                
                for x in range(x_start, x_end + 1):
                    rhs = (x ** 3 + a * x + b) % p
                    # Use the quadratic residue property to find y values
                    y = pow(rhs, (p + 1) // 4, p) if rhs != 0 else 0
                    if (y * y) % p == rhs:
                        x_curve.extend([x, x])
                        y_curve.extend([y, (-y) % p])
        else:
            # If no points provided, just compute some points around the origin
            for x in range(min(100, p)):
                rhs = (x ** 3 + a * x + b) % p
                y = pow(rhs, (p + 1) // 4, p) if rhs != 0 else 0
                if (y * y) % p == rhs:
                    x_curve.extend([x, x])
                    y_curve.extend([y, (-y) % p])
    
    if x_curve:  # Only plot if we found points
        ax.scatter(x_curve, y_curve, color='blue', s=20, label='Field Points')

    # Plot provided points
    valid_points = [pt for pt in points if is_numeric_point(pt)] if points else []
    if valid_points:
        xs, ys = zip(*valid_points)
        ax.scatter(xs, ys, color='blue', s=40, label='Points')

        # Draw labels if valid
        if labels and len(labels) == len(points):
            for (x, y), label in zip(valid_points, labels):
                ax.text(x + 0.3, y + 0.3, str(label), fontsize=9, color='black')

    # Highlight points and show progression
    if is_numeric_point(highlight):
        hx, hy = highlight
        if prev_point and is_numeric_point(prev_point):
            px, py = prev_point
            # Draw arrow from previous to current point
            ax.annotate('',
                xy=(hx, hy), xycoords='data',
                xytext=(px, py), textcoords='data',
                arrowprops=dict(arrowstyle='->', color='red', lw=2))
            # Show previous point in lighter red
            ax.scatter([px], [py], color='salmon', s=80, alpha=0.5, label='Previous')
        # Show current point in bright red
        ax.scatter([hx], [hy], color='red', s=80, label='Current')

    ax.set_title(f"y² = x³ + {a}x + {b} (mod {p})")
    ax.set_xlabel('x')
    ax.set_ylabel('y')
    ax.legend()
    ax.grid(True)
    ax.set_aspect('equal', 'box')
    # Set appropriate axis limits based on curve size and points
    if x_curve or (points and len(points) > 0):
        # Get all x and y coordinates
        all_x = x_curve.copy()
        all_y = y_curve.copy()
        if points:
            all_x.extend([pt[0] for pt in points if is_numeric_point(pt)])
            all_y.extend([pt[1] for pt in points if is_numeric_point(pt)])
        
        x_min, x_max = min(all_x), max(all_x)
        y_min, y_max = min(all_y), max(all_y)
        x_range = max(x_max - x_min, 1)  # Avoid zero range
        y_range = max(y_max - y_min, 1)  # Avoid zero range
        
        # Add padding
        padding_x = x_range * 0.2
        padding_y = y_range * 0.2
        ax.set_xlim(x_min - padding_x, x_max + padding_x)
        ax.set_ylim(y_min - padding_y, y_max + padding_y)
    else:
        # Default view if no points
        ax.set_xlim(-1, min(20, p))
        ax.set_ylim(-1, min(20, p))

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
