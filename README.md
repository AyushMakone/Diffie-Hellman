# Diffie-Hellman Key Exchange Visualizer with MITM Attack Demonstration

A clean, modern, and beginner-friendly interactive visualizer designed for students and educators to understand **Diffie-Hellman Key Exchange** and the **Man-in-the-Middle (MITM) Attack**.

---

## 🌟 Overview

Diffie-Hellman allows two parties who have never met before to create a shared secret key across an open, public channel. However, because plain Diffie-Hellman does **not authenticate** identities, an active attacker in the middle can intercept the communication, impersonate both parties, and completely compromise security.

This visualizer breaks down the entire process into 3 simple, interactive sections:

### 1. Diffie-Hellman Key Exchange (Normal & Secure)
- **Simple Concept:** Understand how two people (Alice and Bob) exchange public values to generate the exact same secret key without ever exposing their private numbers.
- **Canonical Numbers:** Uses clean, integer-friendly parameters ($p = 23, g = 5, a = 6, b = 15$).
- **Step-by-Step Walkthrough:**
  1. Public setup: Agree on prime modulus $p$ and base generator $g$.
  2. Private choices: Alice picks secret $a$, Bob picks secret $b$.
  3. Public exchange: Alice sends $A = g^a \bmod p$, Bob sends $B = g^b \bmod p$.
  4. Secret key derived: Both arrive at the identical key $K = 2$.
- **Interactive Controls:** Start Simulation (with auto-play / pause), step-by-step navigation, and Reset button.

### 2. MITM Attack Demonstration
- **The Attacker (Eve):** An active attacker named Eve cuts the wire and sits in between Alice and Bob.
- **Visual Interception:** Watch Eve intercept Alice's public value ($A = 8$) and Bob's public value ($B = 19$), replacing them with her own spoofed values ($E_1 = 4, E_2 = 10$).
- **Two Separate Keys:**
  - Alice and Eve share Secret Key **9**.
  - Bob and Eve share Secret Key **14**.
  - Alice's Key ($9$) $\neq$ Bob's Key ($14$) — Alice and Bob have **no shared secret**.
- **Live Message Interception:** Type a message from Alice to Bob, and watch Eve intercept, decrypt, alter, and re-encrypt it without Alice or Bob knowing.

### 3. Comparison: Normal DH vs. MITM Attack
- **Side-by-Side Comparison:** Compares Normal DH vs. MITM Attack across channel state, keys created, attacker capabilities, and privacy.

---

## 🎨 Design Features

- **Blue & Purple Theme:** Sleek dark canvas (`#090d16`) with electric blue for Alice, royal indigo for Bob, and neon purple for Eve.
- **Interactive Animations:** Moving packets, wire-cut indicators, and pulsing card highlights.
- **Responsive:** Optimized for mobile phones, tablets, and desktop displays.
- **Beginner-Friendly:** Clear language, simple math cards, and zero cryptographic jargon overload.

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (version 18 or newer recommended)

### Installation & Running Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/systemslibrarian/crypto-lab-diffie-hellman-mitm.git
   cd crypto-lab-diffie-hellman-mitm
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the local development server:**
   ```bash
   npm run dev
   ```
   Open the displayed URL (e.g. `http://localhost:5173`) in your browser.

4. **Build for production:**
   ```bash
   npm run build
   ```

5. **Run engine tests:**
   ```bash
   npm test
   ```
