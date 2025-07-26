
## ECC Playground – Visual Cryptographic Simulator

**ECC Playground** is a graphical simulator for visualizing Elliptic Curve Cryptography (ECC) operations such as scalar multiplication and point addition. It's designed to help understand the mechanics of ECC through step-by-step visualizations.

---

### Features

- Visualize scalar multiplication on elliptic curves
- Step-by-step display of ECC point operations
- Support for both preset and custom curve parameters
- Input base points and scalar values
- Export results in text or JSON format
- Interactive interface using Streamlit

---

### Setup Instructions

1. Ensure Python 3.x is installed
2. Clone this repository or download the source code
3. Open a terminal in the project root directory
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Run the application:
   ```bash
   streamlit run app.py
   ```

---

### Project Structure

| File | Description |
|------|-------------|
| `app.py` | Streamlit-based application entry point |
| `ecc_math.py` | ECC arithmetic logic |
| `curves.py` | Preset and custom curve definitions |
| `visualizer.py` | ECC curve visualization using matplotlib |
| `export_utils.py` | Export results to JSON/text |
| `requirements.txt` | Required Python packages |

---

### Troubleshooting

- Ensure `python` and `pip` are properly installed
- Use `python3` and `pip3` if needed (Linux/macOS)
- If `streamlit` is not found, install it with:
  ```bash
  pip install streamlit
  ```

---

### License

This project is licensed under the [MIT License](LICENSE).
