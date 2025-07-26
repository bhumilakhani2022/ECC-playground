# Export utilities for ECC Playground
import json

def export_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def export_to_text(data, filename):
    with open(filename, 'w') as f:
        for k, v in data.items():
            f.write(f"{k}: {v}\n")