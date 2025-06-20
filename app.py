import streamlit as st
import matplotlib.pyplot as plt
from ecc_math import scalar_mult, is_on_curve, get_public_key, ecdh_shared_secret, ecdsa_sign, ecdsa_verify
from curves import get_preset_curves, make_custom_curve
from visualizer import plot_curve_and_points
import ecies
import ecc_math
import qr_utils
import blockchain
import numpy as np
import time
from io import BytesIO

st.set_page_config(page_title="ECC Playground", layout="wide")
st.title("🔐 ECC Playground – Visual Cryptographic Simulator")
st.markdown("""
This interactive playground lets you explore Elliptic Curve Cryptography (ECC) visually. Use the tabs below to navigate between Scalar Multiplication, ECDH Key Exchange, and ECDSA Digital Signature.
""")

# Sidebar for curve selection and custom curve
st.sidebar.header("Curve Selection")
curves = get_preset_curves()
curve_names = list(curves.keys()) + ["Custom"]
curve_choice = st.sidebar.selectbox("Choose a curve", curve_names)

if curve_choice == "Custom":
    a = int(st.sidebar.number_input("a", value=2))
    b = int(st.sidebar.number_input("b", value=2))
    p = int(st.sidebar.number_input("p (prime)", value=17))
    gx = int(st.sidebar.number_input("Gx", value=5))
    gy = int(st.sidebar.number_input("Gy", value=1))
    n = int(st.sidebar.number_input("n (order)", value=19))
    curve = make_custom_curve(a, b, p, (gx, gy), n)
else:
    curve = curves[curve_choice]

st.sidebar.markdown("---")

# --- Top Navigation Tabs ---
tabs = st.tabs([
    "Scalar Multiplication",
    "ECDH Key Exchange",
    "ECDSA Digital Signature",
    "ECIES Encryption",
    "Point Compression",
    "QR Code Utils",
    "Blockchain Simulator",
    "ECC vs RSA",
    "Side-Channel Demo"
])

# --- Scalar Multiplication Tab ---
with tabs[0]:
    col1, col2 = st.columns([2, 3])
    with col1:
        st.subheader("Curve Parameters")
        st.json({k: v for k, v in curve.items() if k in ['a', 'b', 'p', 'G', 'n']})
        scalar = st.number_input("Scalar k", min_value=1, value=2)
        compute = st.button("Compute k*G")
        st.markdown("---")
        st.info("You can change the curve or scalar and click Compute to see the result.")
    with col2:
        st.subheader("Visualization")
        def get_curve_params(curve):
            return tuple(curve.get(k) for k in ['a', 'b', 'p', 'G', 'n'])
        recompute = False
        show_visualization = False
        if compute:
            G = curve['G']
            if not is_on_curve(G, curve['a'], curve['b'], curve['p']):
                st.error("Base point G is not on the curve!")
            else:
                result, steps = scalar_mult(scalar, G, curve['a'], curve['p'], return_steps=True)
                st.session_state['last_result'] = result
                st.session_state['last_steps'] = steps
                st.session_state['last_G'] = G
                st.session_state['last_curve'] = get_curve_params(curve)
                st.session_state['last_scalar'] = scalar
                st.session_state['autoplay'] = False
                st.session_state['step_idx'] = 0
                recompute = True
                show_visualization = True
        elif ('last_steps' in st.session_state and
            st.session_state.get('last_curve') == get_curve_params(curve) and
            st.session_state.get('last_scalar') == scalar):
            steps = st.session_state['last_steps']
            result = st.session_state['last_result']
            G = st.session_state['last_G']
            show_visualization = True
        if show_visualization:
            max_step = len(steps)
            colA, colB = st.columns([1, 2])
            with colA:
                if st.button("Auto-play", key="autoplay_btn"):
                    st.session_state['autoplay'] = True
                if st.button("Stop", key="stop_btn"):
                    st.session_state['autoplay'] = False
            with colB:
                step_idx = st.slider("Step", 0, max_step, st.session_state.get('step_idx', 0), key="slider_step")
                st.session_state['step_idx'] = step_idx
            # Auto-play logic
            if st.session_state.get('autoplay', False) and st.session_state['step_idx'] < max_step:
                time.sleep(0.5)
                st.session_state['step_idx'] += 1
                st.experimental_rerun()
            # Show up to the selected step
            points = [G] + [pt for pt, _ in steps[:st.session_state['step_idx']]]
            # Label G, then 2G, 3G, ...
            labels = ["G"] + [f"Step {i+1}" for i in range(len(points)-1)]
            highlight = points[-1] if points else None
            fig, ax = plot_curve_and_points(curve, points=points, highlight=highlight, labels=labels)
            st.pyplot(fig)
            st.success(f"Result: {scalar} * G = {result}")
            if st.session_state['step_idx'] > 0:
                st.info(steps[st.session_state['step_idx']-1][1])
            else:
                st.info("Start at G")
        else:
            st.info("Enter a scalar and click Compute to see the result.")

# --- ECDH Key Exchange Tab ---
with tabs[1]:
    st.subheader("Elliptic Curve Diffie-Hellman (ECDH) Key Exchange")
    st.markdown("""
    **Step 1:** Alice and Bob each choose a private key (a, b).<br>
    **Step 2:** Each computes their public key: `A = a*G`, `B = b*G`.<br>
    **Step 3:** Each computes the shared secret: `S = a*B = b*A`.<br>
    <br>
    All calculations are done on the selected curve.
    """, unsafe_allow_html=True)
    ecdh_col1, ecdh_col2 = st.columns(2)
    with ecdh_col1:
        alice_priv = st.number_input("Alice's Private Key", min_value=1, value=2, key="ecdh_alice_priv")
        bob_priv = st.number_input("Bob's Private Key", min_value=1, value=3, key="ecdh_bob_priv")
        ecdh_compute = st.button("Compute ECDH Step-by-Step")
    with ecdh_col2:
        ecdh_result = st.empty()
    if ecdh_compute:
        try:
            G = curve['G']
            a_pub = get_public_key(alice_priv, G, curve['a'], curve['p'])
            b_pub = get_public_key(bob_priv, G, curve['a'], curve['p'])
            shared1 = ecdh_shared_secret(alice_priv, b_pub, curve['a'], curve['p'])
            shared2 = ecdh_shared_secret(bob_priv, a_pub, curve['a'], curve['p'])
            match = shared1 == shared2
            st.markdown(f"**Alice's Public Key (A = a*G):** {a_pub}")
            st.markdown(f"**Bob's Public Key (B = b*G):** {b_pub}")
            st.markdown(f"**Alice computes shared secret (a*B):** {shared1}")
            st.markdown(f"**Bob computes shared secret (b*A):** {shared2}")
            st.markdown(f"**Do the shared secrets match?** {'✅ Yes' if match else '❌ No'}")
            # Visualization: plot G, Alice's pub, Bob's pub, shared secret
            points = [G, a_pub, b_pub, shared1]
            labels = ['G', "Alice's Public", "Bob's Public", 'Shared Secret']
            fig, ax = plot_curve_and_points(curve, points=points, highlight=shared1, labels=labels)
            st.pyplot(fig)
            st.info("The shared secret is the same for both Alice and Bob, even though they never shared their private keys!")
        except Exception as e:
            ecdh_result.error(f"Error: {e}")

# --- ECDSA Digital Signature Tab ---
with tabs[2]:
    st.subheader("Elliptic Curve Digital Signature Algorithm (ECDSA)")
    with st.expander("Sign a Message (ECDSA)"):
        msg = st.text_input("Message to Sign", value="Hello, ECC!", key="ecdsa_sign_msg")
        priv = st.number_input("Private Key", min_value=1, value=2, key="ecdsa_sign_priv")
        sign_btn = st.button("Sign Message", key="ecdsa_sign_btn")
        sign_result = st.empty()
        if sign_btn:
            try:
                G = curve['G']
                r, s = ecdsa_sign(msg.encode(), priv, G, curve['a'], curve['p'], curve['n'])
                sign_result.success(f"Signature: (r={r}, s={s})")
                st.session_state['ecdsa_last_r'] = r
                st.session_state['ecdsa_last_s'] = s
            except Exception as e:
                sign_result.error(f"Error: {e}")
    with st.expander("Verify a Signature (ECDSA)"):
        vmsg = st.text_input("Message to Verify", value="Hello, ECC!", key="ecdsa_verify_msg")
        r = st.text_input("Signature r", value=str(st.session_state.get('ecdsa_last_r', 1)), key="ecdsa_verify_r")
        s = st.text_input("Signature s", value=str(st.session_state.get('ecdsa_last_s', 1)), key="ecdsa_verify_s")
        pub_x = st.text_input("Public Key x", value=str(curve['G'][0]), key="ecdsa_verify_pubx")
        pub_y = st.text_input("Public Key y", value=str(curve['G'][1]), key="ecdsa_verify_puby")
        verify_btn = st.button("Verify Signature", key="ecdsa_verify_btn")
        verify_result = st.empty()
        if verify_btn:
            try:
                G = curve['G']
                pub = (int(pub_x), int(pub_y))
                valid = ecdsa_verify(vmsg.encode(), (int(r), int(s)), pub, G, curve['a'], curve['p'], curve['n'])
                verify_result.success(f"Signature valid: {valid}")
            except Exception as e:
                verify_result.error(f"Error: {e}")

# --- ECIES Encryption Tab ---
with tabs[3]:
    st.subheader("ECIES Encryption/Decryption")
    st.markdown("Encrypt and decrypt messages using ECIES (ECC + AES).")
    msg = st.text_area("Message to Encrypt", value="Secret message", key="ecies_msg")
    pub_x = st.text_input("Recipient Public Key x", value=str(curve['G'][0]), key="ecies_pubx")
    pub_y = st.text_input("Recipient Public Key y", value=str(curve['G'][1]), key="ecies_puby")
    encrypt_btn = st.button("Encrypt Message", key="ecies_encrypt_btn")
    decrypt_btn = st.button("Decrypt Last Ciphertext", key="ecies_decrypt_btn")
    ecies_result = st.empty()
    if encrypt_btn:
        try:
            pub = (int(pub_x), int(pub_y))
            G = curve['G']
            enc = ecies.ecies_encrypt(msg.encode(), pub, G, curve['a'], curve['p'], curve['n'])
            st.session_state['last_ecies'] = enc
            ecies_result.success(f"Encrypted! Ephemeral pub: {enc['ephemeral_pub']}, IV: {enc['iv']}, Ciphertext: {enc['ciphertext']}")
        except Exception as e:
            ecies_result.error(f"Error: {e}")
    if decrypt_btn:
        try:
            priv = st.number_input("Your Private Key", min_value=1, value=2, key="ecies_priv")
            G = curve['G']
            enc = st.session_state.get('last_ecies')
            if not enc:
                ecies_result.info("No ciphertext to decrypt.")
            else:
                dec = ecies.ecies_decrypt(enc, priv, G, curve['a'], curve['p'], curve['n'])
                ecies_result.success(f"Decrypted message: {dec.decode(errors='replace')}")
        except Exception as e:
            ecies_result.error(f"Error: {e}")

# --- Point Compression Tab ---
with tabs[4]:
    st.subheader("Point Compression/Decompression")
    st.markdown("Compress and decompress ECC points. Useful for QR codes and compact storage.")
    px = st.text_input("Point x", value=str(curve['G'][0]), key="compress_x")
    py = st.text_input("Point y", value=str(curve['G'][1]), key="compress_y")
    compress_btn = st.button("Compress Point", key="compress_btn")
    decompress_btn = st.button("Decompress Point", key="decompress_btn")
    comp_result = st.empty()
    if compress_btn:
        try:
            P = (int(px), int(py))
            comp = ecc_math.compress_point(P)
            comp_result.success(f"Compressed: {comp}")
        except Exception as e:
            comp_result.error(f"Error: {e}")
    if decompress_btn:
        try:
            x = int(px)
            ybit = int(st.number_input("y parity bit (0 or 1)", min_value=0, max_value=1, value=0, key="ybit"))
            dec = ecc_math.decompress_point(x, ybit, curve['a'], curve['b'], curve['p'])
            comp_result.success(f"Decompressed: {dec}")
        except Exception as e:
            comp_result.error(f"Error: {e}")

# --- QR Code Utils Tab ---
with tabs[5]:
    st.subheader("QR Code Utilities")
    st.markdown("Generate or scan QR codes for keys, points, or messages.")
    qr_data = st.text_input("Data to encode as QR", value="Hello QR!", key="qr_data")
    qr_btn = st.button("Generate QR Code", key="qr_btn")
    qr_result = st.empty()
    if qr_btn:
        try:
            img = qr_utils.generate_qr(qr_data)
            buf = BytesIO()
            img.save(buf, format="PNG")
            st.image(buf.getvalue())
            qr_result.success("QR code generated.")
        except Exception as e:
            qr_result.error(f"Error: {e}")
    st.markdown("---")
    st.markdown("### Scan QR Code from Image")
    uploaded_file = st.file_uploader("Upload QR code image", type=["png", "jpg", "jpeg"], key="qr_upload")
    scan_result = st.empty()
    if uploaded_file is not None:
        try:
            with open("temp_qr_upload.png", "wb") as f:
                f.write(uploaded_file.read())
            decoded = qr_utils.scan_qr("temp_qr_upload.png")
            scan_result.success(f"Decoded QR data: {decoded}")
        except Exception as e:
            scan_result.error(f"Error: {e}")

# --- Blockchain Simulator Tab ---
with tabs[6]:
    st.subheader("Blockchain Mini-Simulator")
    st.markdown("A simple blockchain with ECDSA-signed transactions.")
    if 'blockchain' not in st.session_state or st.session_state.get('blockchain_curve') != curve:
        st.session_state['blockchain'] = blockchain.Blockchain(curve)
        st.session_state['blockchain_curve'] = curve
    bc = st.session_state['blockchain']
    st.markdown("### Add Transaction")
    sender = st.text_input("Sender", value="Alice", key="bc_sender")
    recipient = st.text_input("Recipient", value="Bob", key="bc_recipient")
    amount = st.number_input("Amount", min_value=1, value=10, key="bc_amount")
    priv_key = st.text_input("Sender Private Key (for ECDSA sign)", value="2", key="bc_priv")
    add_tx_btn = st.button("Add Transaction", key="bc_add_tx")
    add_tx_result = st.empty()
    if add_tx_btn:
        try:
            tx = bc.add_transaction(sender, recipient, amount, int(priv_key))
            add_tx_result.success(f"Transaction added and signed: {tx.to_dict()}")
        except Exception as e:
            add_tx_result.error(f"Error: {e}")
    st.markdown("### Mine Block")
    mine_btn = st.button("Mine Block", key="bc_mine")
    mine_result = st.empty()
    if mine_btn:
        try:
            block = bc.mine_block()
            mine_result.success(f"Block mined! Hash: {block.hash}")
        except Exception as e:
            mine_result.error(f"Error: {e}")
    st.markdown("### Blockchain")
    for block in bc.chain:
        st.markdown(f"**Block {block.index}** | Hash: `{block.hash[:12]}...` | Prev: `{block.prev_hash[:12]}...`")
        for tx in block.transactions:
            st.json(tx.to_dict())
    st.markdown("### Verify Chain")
    verify_btn = st.button("Verify Blockchain", key="bc_verify")
    verify_result = st.empty()
    if verify_btn:
        valid, msg = bc.verify_chain()
        if valid:
            verify_result.success(f"✅ {msg}")
        else:
            verify_result.error(f"❌ {msg}")

# --- ECC vs RSA Tab ---
with tabs[7]:
    st.subheader("ECC vs RSA Security Comparison")
    st.markdown("Compare ECC and RSA key sizes, security, and performance.")
    st.info("ECC offers similar security to RSA with much smaller key sizes. For example, 256-bit ECC ≈ 3072-bit RSA.")
    st.markdown("| ECC Key Size | RSA Key Size | Security Level (bits) |\n|---|---|---|\n| 160 | 1024 | 80 |\n| 224 | 2048 | 112 |\n| 256 | 3072 | 128 |\n| 384 | 7680 | 192 |\n| 521 | 15360 | 256 |")

# --- Side-Channel Demo Tab ---
with tabs[8]:
    st.subheader("Side-Channel Attack Demo: Timing Attack on Scalar Multiplication")
    st.markdown("""
    This demo simulates a timing attack on ECC scalar multiplication. If the implementation is not constant-time, the time taken can leak information about the secret key's bits! Try different secret keys and see the timing differences.
    """)
    G = curve['G']
    a, p = curve['a'], curve['p']
    st.markdown("#### Simulate Timing for Different Secret Keys")
    keys = [3, 7, 15, 31, 63, 127, 255]
    times = []
    for k in keys:
        start = time.perf_counter()
        scalar_mult(k, G, a, p)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
    st.bar_chart({"Secret Key": keys, "Time (s)": times})
    st.markdown("""
    **Notice:** The time increases with the number of bits set in the key (due to the double-and-add algorithm). In real cryptography, always use constant-time algorithms to prevent such leaks!
    """) 