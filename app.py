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

def format_key(key):
    """Formats a key (int or tuple) as a hex string for display."""
    if isinstance(key, tuple):
        # Assuming it's a public key (x, y)
        return f"({hex(key[0])}, {hex(key[1])})"
    elif isinstance(key, int):
        # Assuming it's a private key or part of a signature
        return hex(key)
    # Fallback for other types
    return str(key)


st.set_page_config(page_title="ECC Playground", layout="wide")
st.title("🔐 ECC Playground – Visual Cryptographic Simulator")
st.markdown("""
This interactive playground lets you explore Elliptic Curve Cryptography (ECC) visually. Use the tabs below to navigate between Scalar Multiplication, ECDH Key Exchange, and ECDSA Digital Signature.
""")

# Sidebar for curve selection and custom curve
st.sidebar.header("Curve Selection")
curves = get_preset_curves()
curve_names = list(curves.keys()) + ["Custom"]
# Only one demo button, with a unique key
show_demo_pressed = st.sidebar.button("Show Demo Curve (Toy Curve)", key="show_demo_btn")
if show_demo_pressed:
    st.sidebar.success("Now select 'Toy Curve' from the dropdown below if it is not already selected.")
# Always ensure 'curve_choice' is set
if 'curve_choice' not in st.session_state or st.session_state['curve_choice'] not in curve_names:
    st.session_state['curve_choice'] = 'Toy Curve'
curve_choice = st.sidebar.selectbox("Choose a curve", curve_names, key='curve_choice')

# Fallback: if the selected curve is not found, use Toy Curve
if curve_choice == "Custom":
    a = int(st.sidebar.number_input("a", value=2))
    b = int(st.sidebar.number_input("b", value=2))
    p = int(st.sidebar.number_input("p (prime)", value=17))
    gx = int(st.sidebar.number_input("Gx", value=5))
    gy = int(st.sidebar.number_input("Gy", value=1))
    n = int(st.sidebar.number_input("n (order)", value=19))
    curve = make_custom_curve(a, b, p, (gx, gy), n)
else:
    curve = curves.get(curve_choice, curves['Toy Curve'])

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
        # Add a button to switch to demo curve if p is large
        if curve['p'] > 1000:
            st.warning("Curve not visualized for large p. For visualization, use a small prime (e.g., p=17).")
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
                # Remove Auto-play and Stop buttons for compatibility
                pass
            with colB:
                step_idx = st.slider("Step", 0, max_step, st.session_state.get('step_idx', 0), key="slider_step")
                st.session_state['step_idx'] = step_idx
            # Show up to the selected step
            points = [G]  # Start with base point
            for step in steps[:st.session_state['step_idx']]:
                if len(step) == 4:  # New format (step_num, op_type, current, previous)
                    _, _, current, _ = step
                    points.append(current)
                elif len(step) == 3:  # Initial point format (0, "start", point)
                    _, _, point = step
                    points.append(point)
                    
            # Label G, then 2G, 3G, ...
            labels = ["G"] + [f"Step {i+1}" for i in range(len(points)-1)]
            highlight = points[-1] if points else None
            
            # Get previous point for showing progression
            prev_point = None
            if st.session_state['step_idx'] > 0:
                step = steps[st.session_state['step_idx']-1]
                if len(step) == 4:  # New format
                    _, _, _, prev_point = step
            
            fig, ax = plot_curve_and_points(curve, points=points, highlight=highlight, labels=labels, prev_point=prev_point)
            st.pyplot(fig)
            st.success(f"Result: {scalar} * G = {result}")
            if st.session_state['step_idx'] > 0:
                # Show explanation from the step
                step = steps[st.session_state['step_idx']-1]
                explanation = step[2] if len(step) == 3 else step[3]  # Get explanation based on format
                st.info(explanation)
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
    st.markdown("""
    **ECDSA** is a digital signature scheme based on elliptic curves. It allows you to sign a message with your private key, and anyone can verify the signature using your public key.
    
    - **Sign:** Enter a message and your private key. The app will generate a signature (r, s).
    - **Verify:** Enter the message, signature (r, s), and public key (x, y) to check if the signature is valid.
    """)
    with st.expander("Sign a Message (ECDSA)"):
        msg = st.text_input("Message to Sign", value="Hello, ECC!", key="ecdsa_sign_msg", help="The message you want to sign.")
        priv = st.number_input("Private Key", min_value=1, value=2, key="ecdsa_sign_priv", help="Your private key for signing.")
        sign_btn = st.button("Sign Message", key="ecdsa_sign_btn")
        sign_result = st.empty()
        if sign_btn:
            try:
                G = curve['G']
                r, s = ecdsa_sign(msg.encode(), priv, G, curve['a'], curve['p'], curve['n'])
                sign_result.success(f"Signature: (r={r}, s={s})\nPublic Key: {get_public_key(priv, G, curve['a'], curve['p'])}")
                st.session_state['ecdsa_last_r'] = r
                st.session_state['ecdsa_last_s'] = s
                st.session_state['ecdsa_last_pub'] = get_public_key(priv, G, curve['a'], curve['p'])
            except Exception as e:
                sign_result.error(f"Error: {e}")
    with st.expander("Verify a Signature (ECDSA)"):
        vmsg = st.text_input("Message to Verify", value="Hello, ECC!", key="ecdsa_verify_msg", help="The message whose signature you want to verify.")
        r = st.text_input("Signature r", value=str(st.session_state.get('ecdsa_last_r', 1)), key="ecdsa_verify_r", help="The r value from the signature.")
        s = st.text_input("Signature s", value=str(st.session_state.get('ecdsa_last_s', 1)), key="ecdsa_verify_s", help="The s value from the signature.")
        pub_x = st.text_input("Public Key x", value=str(st.session_state.get('ecdsa_last_pub', (curve['G'][0], curve['G'][1]))[0]), key="ecdsa_verify_pubx", help="x coordinate of the public key.")
        pub_y = st.text_input("Public Key y", value=str(st.session_state.get('ecdsa_last_pub', (curve['G'][0], curve['G'][1]))[1]), key="ecdsa_verify_puby", help="y coordinate of the public key.")
        verify_btn = st.button("Verify Signature", key="ecdsa_verify_btn")
        verify_result = st.empty()
        if verify_btn:
            try:
                G = curve['G']
                pub = (int(pub_x), int(pub_y))
                valid = ecdsa_verify(vmsg.encode(), (int(r), int(s)), pub, G, curve['a'], curve['p'], curve['n'])
                if valid:
                    verify_result.success("Signature is VALID. This message was signed by the holder of the private key for this public key.")
                else:
                    verify_result.error("Signature is INVALID. The message or signature does not match the public key.")
            except Exception as e:
                verify_result.error(f"Error: {e}")

# --- ECIES Encryption Tab ---
with tabs[3]:
    st.subheader("ECIES Encryption/Decryption")
    st.markdown("Encrypt and decrypt messages using ECIES (ECC + AES).")

    # To ensure the default example works, we'll derive the public key from a default private key.
    # The user can then modify either the private key for decryption or the public key for encryption.
    default_recipient_priv_key = 2
    default_recipient_pub_key = get_public_key(default_recipient_priv_key, curve['G'], curve['a'], curve['p'])

    msg = st.text_area("Message to Encrypt", value="Secret message", key="ecies_msg")
    pub_x = st.text_input("Recipient Public Key x", value=str(default_recipient_pub_key[0]), key="ecies_pubx")
    pub_y = st.text_input("Recipient Public Key y", value=str(default_recipient_pub_key[1]), key="ecies_puby")
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
            priv = st.number_input("Your Private Key", min_value=1, value=default_recipient_priv_key, key="ecies_priv")
            G = curve['G']
            enc = st.session_state.get('last_ecies')
            if not enc:
                ecies_result.info("No ciphertext to decrypt.")
            else:
                dec = ecies.ecies_decrypt(enc, priv, G, curve['a'], curve['b'], curve['p'], curve['n'])
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
            # The compressed point is now a tuple (prefix, x)
            # We get it from the input fields px and the prefix from the y-parity bit
            px_val = int(px)
            ybit = int(st.number_input("y parity bit (0 for even, 1 for odd)", min_value=0, max_value=1, value=0, key="ybit"))
            prefix = 2 + ybit
            compressed_point = (prefix, px_val)
            
            dec = ecc_math.decompress_point(compressed_point, curve['a'], curve['b'], curve['p'])
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
    st.markdown("A simple blockchain with ECDSA-signed transactions and wallet management.")
    if 'blockchain' not in st.session_state or st.session_state.get('blockchain_curve') != curve:
        st.session_state['blockchain'] = blockchain.Blockchain(curve)
        st.session_state['blockchain_curve'] = curve
    bc = st.session_state['blockchain']
    # --- Wallet Management ---
    st.markdown("### Wallets")
    if 'wallets' not in st.session_state:
        st.session_state['wallets'] = []
    wallets = st.session_state['wallets']
    if st.button("Create New Wallet", key="bc_create_wallet"):
        priv = np.random.randint(2, curve['n']-1)
        pub = get_public_key(priv, curve['G'], curve['a'], curve['p'])
        wallets.append({'priv': priv, 'pub': pub})
        st.success(f"Wallet created! Public key: {pub}")
    if wallets:
        st.markdown("**Your Wallets:**")
        for i, w in enumerate(wallets):
            st.code(f"Wallet {i+1}:\n  Private: {format_key(w['priv'])}...\n  Public: {format_key(w['pub'])}...")
    else:
        st.info("No wallets yet. Click 'Create New Wallet' to get started.")
    # --- Transaction Creation ---
    st.markdown("### Add Transaction")
    if wallets:
        sender_idx = st.selectbox("Sender Wallet", options=list(range(len(wallets))), format_func=lambda i: f"Wallet {i+1}", key="bc_sender_wallet")
        recipient_idx = st.selectbox("Recipient Wallet", options=list(range(len(wallets))), format_func=lambda i: f"Wallet {i+1}", key="bc_recipient_wallet")
        amount = st.number_input("Amount", min_value=1, value=10, key="bc_amount2", help="Amount to transfer.")
        add_tx_btn = st.button("Add Transaction", key="bc_add_tx2")
        add_tx_result = st.empty()
        if add_tx_btn:
            try:
                sender = f"Wallet {sender_idx+1}"
                recipient = f"Wallet {recipient_idx+1}"
                priv_key = wallets[sender_idx]['priv']
                tx = bc.add_transaction(sender, recipient, amount, priv_key)
                add_tx_result.success(f"Transaction added and signed: {tx.to_dict()}")
            except Exception as e:
                add_tx_result.error(f"Error: {e}")
    else:
        st.info("Create at least two wallets to send transactions.")
    # --- Transaction History ---
    st.markdown("### Pending Transactions")
    if bc.pending:
        st.table([{**tx.to_dict(), 'pubkey': format_key(tx.pubkey)} for tx in bc.pending])
    else:
        st.info("No pending transactions. Add some above before mining.")
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
        st.markdown(f"**Block {block.index}** | Hash: `{block.hash[:12]}...` | Prev: `{block.prev_hash[:12]}...` | Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))}")
        st.table([{**tx.to_dict(), 'pubkey': str(tx.pubkey)} for tx in block.transactions])
    st.markdown("### Verify Chain")
    verify_btn = st.button("Verify Blockchain", key="bc_verify")
    verify_result = st.empty()
    if verify_btn:
        valid, msg = bc.verify_chain()
        if valid:
            verify_result.success(f"✅ {msg}")
        else:
            verify_result.error(f"❌ {msg}")
    st.markdown("### Reset Blockchain")
    if st.button("Reset Blockchain", key="bc_reset"):
        st.session_state['blockchain'] = blockchain.Blockchain(curve)
        st.session_state['blockchain_curve'] = curve
        st.success("Blockchain reset!")
    # --- Transaction History (All) ---
    st.markdown("### All Transactions (Confirmed)")
    all_txs = []
    for block in bc.chain:
        for tx in block.transactions:
            all_txs.append({**tx.to_dict(), 'block': block.index, 'pubkey': str(tx.pubkey)[:30] + "..."})
    if all_txs:
        st.table(all_txs)
    else:
        st.info("No confirmed transactions yet.")

# --- ECC vs RSA Tab ---
with tabs[7]:
    st.subheader("ECC vs RSA Security Comparison")
    st.markdown("""
    **Elliptic Curve Cryptography (ECC)** and **RSA** are two of the most widely used public-key cryptosystems. ECC offers the same level of security as RSA but with much smaller key sizes, making it faster and more efficient for modern applications.
    """)
    st.markdown("### Key Size and Security Comparison")
    st.markdown("| ECC Key Size | RSA Key Size | Security Level (bits) | Performance |\n|---|---|---|---|\n| 160 | 1024 | 80 | ECC: Fast, RSA: Slow |\n| 224 | 2048 | 112 | ECC: Fast, RSA: Slower |\n| 256 | 3072 | 128 | ECC: Very Fast, RSA: Much Slower |\n| 384 | 7680 | 192 | ECC: Fast, RSA: Impractical |\n| 521 | 15360 | 256 | ECC: Fast, RSA: Impractical |")
    st.info("ECC offers similar security to RSA with much smaller key sizes. For example, 256-bit ECC ≈ 3072-bit RSA.")
    st.markdown("### Security Level Calculator")
    sec_level = st.slider("Desired Security Level (bits)", min_value=80, max_value=256, value=128, step=8)
    ecc_size = {80:160, 112:224, 128:256, 192:384, 256:521}.get(sec_level, 256)
    rsa_size = {80:1024, 112:2048, 128:3072, 192:7680, 256:15360}.get(sec_level, 3072)
    st.success(f"For {sec_level}-bit security: ECC key size ≈ {ecc_size} bits, RSA key size ≈ {rsa_size} bits.")
    st.markdown("""
    **Why is ECC more efficient?**
    - Smaller keys, signatures, and certificates.
    - Faster computations (especially for mobile/IoT).
    - Lower bandwidth and storage requirements.
    
    **Where is ECC used?**
    - Bitcoin, Ethereum, and most cryptocurrencies
    - TLS/SSL (HTTPS)
    - Modern messaging apps (Signal, WhatsApp)
    - Mobile devices and smart cards
    
    **When to use RSA?**
    - Legacy systems
    - When interoperability with old hardware/software is required
    - For learning and historical context
    """)

# --- Side-Channel Demo Tab ---
with tabs[8]:
    st.subheader("Side-Channel Attack Demo: Timing Attack on Scalar Multiplication")
    st.markdown("""
    **Side-channel attacks** exploit information leaked by cryptographic implementations, such as timing, power usage, or electromagnetic emissions. Here, you can simulate a real-world timing attack on ECC scalar multiplication.
    
    **Scenario:**
    Imagine a server uses ECC to sign messages with a secret key. An attacker can send requests and measure how long each operation takes. If the implementation is not constant-time, the attacker can recover the secret key!
    """)
    G = curve['G']
    a, p = curve['a'], curve['p']
    st.markdown("#### Set the Victim's Secret Key")
    secret_key = st.slider("Victim's Secret Key (hidden from attacker)", min_value=1, max_value=50, value=17, key="sc_secret")
    mode = st.radio("Scalar Multiplication Algorithm", ["Non-Constant-Time", "Constant-Time"], key="sc_mode2")
    st.markdown("#### Simulate Attacker Timing All Possible Keys")
    key_range = st.slider("Attacker's Guess Range (keys to try)", min_value=5, max_value=50, value=20, key="sc_range")
    times = []
    def scalar_mult_const_time(k, P, a, p):
        k = int(k)
        Q = None
        for i in range(k.bit_length()-1, -1, -1):
            if Q is not None:
                Q = ecc_math.point_double(Q, a, p)
            if ((k >> i) & 1) or mode == "Constant-Time":
                Q = ecc_math.point_add(Q, P, a, p)
        return Q
    for guess in range(1, key_range+1):
        k = int(guess)
        start = time.perf_counter()
        if mode == "Constant-Time":
            scalar_mult_const_time(k, G, a, p)
        else:
            scalar_mult(k, G, a, p)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
    import matplotlib.pyplot as plt
    import io
    import base64
    fig, ax = plt.subplots()
    ax.plot(range(1, key_range+1), times, label='Timing')
    ax.axvline(secret_key, color='red', linestyle='--', label="Victim's Key")
    ax.set_xlabel('Key Guess')
    ax.set_ylabel('Time (s)')
    ax.set_title('Timing Attack: Time vs. Key Guess')
    ax.legend()
    buf = io.BytesIO()
    fig.savefig(buf, format='png')
    st.image(buf.getvalue(), caption="Timing for each key guess (victim's key in red)")
    st.markdown(f"""
    **What does this show?**
    - In non-constant-time mode, the time for the real key (red line) is often noticeably different.
    - An attacker could spot this and recover the secret key!
    - In constant-time mode, all timings are similar, so the attack fails.
    
    **Try switching modes and changing the victim's key to see the effect.**
    """) 