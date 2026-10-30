// ui.ts — Diffie-Hellman Key Exchange Visualizer with MITM Attack Demonstration

import {
  diffieHellman,
  mitm,
  interceptMessage,
} from './engine.ts';

// Helper for element creation
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  html?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (html !== undefined) node.innerHTML = html;
  return node;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ==========================================================================
   HERO / OVERVIEW SECTION
   ========================================================================== */

function renderHero(): HTMLElement {
  const hero = el('header', 'hero-panel');
  hero.id = 'overview';
  hero.innerHTML = `
    <div class="hero-badge-wrap">
      <span class="hero-badge">Interactive Cryptography Lab</span>
    </div>
    <h1>
      Diffie-Hellman Key Exchange &amp;
      <span class="hero-highlight">MITM Attack Demonstration</span>
    </h1>
    <p class="hero-desc">
      Learn how two people create a shared secret key across the insecure internet without ever meeting in private,
      and see how an attacker named <b>Eve</b> in the middle can secretly trick both of them — and why authentication is the key to stopping it.
    </p>

    <div class="hero-concepts-grid">
      <div class="concept-card">
        <span class="icon">🌐</span>
        <b>1. Public Information</b>
        <p>A prime number (<b>p</b>) and generator base (<b>g</b>) that anyone on the internet can see openly.</p>
      </div>
      <div class="concept-card">
        <span class="icon">🔒</span>
        <b>2. Private Secrets</b>
        <p>Alice and Bob each choose private secret numbers (<b>a</b> and <b>b</b>) that never leave their devices.</p>
      </div>
      <div class="concept-card">
        <span class="icon">🔑</span>
        <b>3. Identical Shared Key</b>
        <p>By exchanging public values, both compute the exact same secret key without ever sending it!</p>
      </div>
    </div>
  `;
  return hero;
}

/* ==========================================================================
   SECTION 1: DIFFIE-HELLMAN KEY EXCHANGE (NORMAL / SECURE)
   ========================================================================== */

function renderDhSection(): HTMLElement {
  const section = el('section', 'lab-section');
  section.id = 'dh-section';

  // Canonical beginner-friendly numbers: p = 23, g = 5, a = 6, b = 15
  let p = 23n;
  let g = 5n;
  let a = 6n;
  let b = 15n;

  let currentStep = 1;
  const TOTAL_STEPS = 4;
  let timer: number | null = null;

  section.innerHTML = `
    <div class="section-tag">Section 1 · Normal Key Exchange</div>
    <h2>1. Diffie-Hellman Key Exchange</h2>
    <p class="section-intro">
      <b>What is Diffie-Hellman?</b> It is a method that allows two parties (Alice and Bob) who have never met before to create a shared secret key over an insecure, public channel.
      Even if an eavesdropper monitors every transmission, they cannot calculate the secret key without solving a mathematically difficult discrete logarithm problem.
    </p>

    <div class="controls-bar">
      <div class="btn-group">
        <button class="btn btn-primary" id="dh-play-btn" type="button">▶ Start Simulation</button>
        <button class="btn btn-ghost" id="dh-reset-btn" type="button">↺ Reset</button>
      </div>

      <div class="stepper-nav">
        <button class="btn btn-ghost" id="dh-prev-btn" type="button" title="Previous step">◀ Prev</button>
        <span class="stepper-counter" id="dh-step-counter">Step 1 of 4</span>
        <button class="btn btn-ghost" id="dh-next-btn" type="button" title="Next step">Next ▶</button>
      </div>

      <div class="field-group">
        <span style="font-size:0.8rem; font-weight:700; color:var(--ink-soft)">Parameters:</span>
        <div class="input-box">
          <label for="dh-p-in">p=</label>
          <input id="dh-p-in" type="text" value="${p}" title="Prime modulus">
        </div>
        <div class="input-box">
          <label for="dh-g-in">g=</label>
          <input id="dh-g-in" type="text" value="${g}" title="Generator base">
        </div>
        <div class="input-box">
          <label for="dh-a-in">a=</label>
          <input id="dh-a-in" type="text" value="${a}" title="Alice secret">
        </div>
        <div class="input-box">
          <label for="dh-b-in">b=</label>
          <input id="dh-b-in" type="text" value="${b}" title="Bob secret">
        </div>
      </div>
    </div>

    <!-- Visual Network Diagram -->
    <div class="visual-network" id="dh-network-view"></div>

    <!-- Step-by-Step Calculation Cards -->
    <div class="step-flow" id="dh-step-flow"></div>

    <!-- Result Outcome Banner -->
    <div id="dh-outcome-view"></div>
  `;

  const playBtn = section.querySelector<HTMLButtonElement>('#dh-play-btn')!;
  const resetBtn = section.querySelector<HTMLButtonElement>('#dh-reset-btn')!;
  const prevBtn = section.querySelector<HTMLButtonElement>('#dh-prev-btn')!;
  const nextBtn = section.querySelector<HTMLButtonElement>('#dh-next-btn')!;
  const counterSpan = section.querySelector<HTMLSpanElement>('#dh-step-counter')!;

  const networkView = section.querySelector<HTMLDivElement>('#dh-network-view')!;
  const stepFlow = section.querySelector<HTMLDivElement>('#dh-step-flow')!;
  const outcomeView = section.querySelector<HTMLDivElement>('#dh-outcome-view')!;

  const inP = section.querySelector<HTMLInputElement>('#dh-p-in')!;
  const inG = section.querySelector<HTMLInputElement>('#dh-g-in')!;
  const inA = section.querySelector<HTMLInputElement>('#dh-a-in')!;
  const inB = section.querySelector<HTMLInputElement>('#dh-b-in')!;

  function stopAutoPlay(): void {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
      playBtn.textContent = '▶ Start Simulation';
      playBtn.classList.remove('btn-danger');
      playBtn.classList.add('btn-primary');
    }
  }

  function toggleAutoPlay(): void {
    if (timer !== null) {
      stopAutoPlay();
    } else {
      if (currentStep >= TOTAL_STEPS) currentStep = 1;
      playBtn.textContent = '⏸ Pause';
      playBtn.classList.remove('btn-primary');
      playBtn.classList.add('btn-danger');
      updateUI();
      timer = window.setInterval(() => {
        if (currentStep < TOTAL_STEPS) {
          currentStep++;
          updateUI();
        } else {
          stopAutoPlay();
        }
      }, 1600);
    }
  }

  function parseInputs(): void {
    try {
      p = BigInt(inP.value.trim());
      g = BigInt(inG.value.trim());
      a = BigInt(inA.value.trim());
      b = BigInt(inB.value.trim());
    } catch {
      p = 23n;
      g = 5n;
      a = 6n;
      b = 15n;
    }
  }

  function updateUI(): void {
    parseInputs();
    const res = diffieHellman(p, g, a, b);

    counterSpan.textContent = `Step ${currentStep} of ${TOTAL_STEPS}`;
    prevBtn.disabled = currentStep <= 1;
    nextBtn.disabled = currentStep >= TOTAL_STEPS;

    // 1. Visual Network Diagram
    const aSent = currentStep >= 3;
    const bSent = currentStep >= 3;
    const keyDone = currentStep >= 4;

    networkView.innerHTML = `
      <div class="parties-container">
        <!-- Alice Card -->
        <div class="party-card party-card--alice">
          <div class="party-header">
            <div class="party-identity">
              <span class="party-avatar">👩</span>
              <span class="party-name">Alice</span>
            </div>
            <span class="party-role party-role--user">Client A</span>
          </div>
          <div class="party-data">
            <div class="data-row">
              <span class="data-label">Private secret (a):</span>
              <span class="data-val data-val--secret">${currentStep >= 2 ? a.toString() : '❓ (hidden)'}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Computes A = gᵃ mod p:</span>
              <span class="data-val data-val--public">${currentStep >= 3 ? res.A.toString() : '…'}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Shared Secret Key:</span>
              <span class="data-val ${keyDone ? 'data-val--key' : ''}">${keyDone ? `K = ${res.sharedFromAlice}` : '…'}</span>
            </div>
          </div>
        </div>

        <!-- Insecure Network Wire -->
        <div class="wire-col">
          <div style="font-size:0.75rem; font-weight:700; color:var(--ink-soft); text-transform:uppercase; letter-spacing:0.06em">
            Public Channel (Internet)
          </div>
          <div class="wire-line">
            <div class="wire-track"></div>
            ${
              aSent
                ? `<span class="wire-packet wire-packet--blue" style="animation: pulse 1.5s infinite">A = ${res.A} ➔</span>`
                : `<span style="font-size:0.75rem; color:var(--ink-dim)">[Awaiting Step 3]</span>`
            }
          </div>
          <div class="wire-line">
            <div class="wire-track"></div>
            ${
              bSent
                ? `<span class="wire-packet wire-packet--purple" style="animation: pulse 1.5s infinite">⇠ B = ${res.B}</span>`
                : `<span style="font-size:0.75rem; color:var(--ink-dim)">[Awaiting Step 3]</span>`
            }
          </div>
          <div style="font-size:0.72rem; color:var(--ink-soft); text-align:center">
            Eavesdropper sees p, g, A, and B openly
          </div>
        </div>

        <!-- Bob Card -->
        <div class="party-card party-card--bob">
          <div class="party-header">
            <div class="party-identity">
              <span class="party-avatar">🧑</span>
              <span class="party-name">Bob</span>
            </div>
            <span class="party-role party-role--user">Client B</span>
          </div>
          <div class="party-data">
            <div class="data-row">
              <span class="data-label">Private secret (b):</span>
              <span class="data-val data-val--secret">${currentStep >= 2 ? b.toString() : '❓ (hidden)'}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Computes B = gᵇ mod p:</span>
              <span class="data-val data-val--public">${currentStep >= 3 ? res.B.toString() : '…'}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Shared Secret Key:</span>
              <span class="data-val ${keyDone ? 'data-val--key' : ''}">${keyDone ? `K = ${res.sharedFromBob}` : '…'}</span>
            </div>
          </div>
        </div>
      </div>
    `;

    // 2. Step Cards
    const stepsData = [
      {
        num: 1,
        title: 'Agree on Public Numbers',
        desc: `Alice and Bob publicly choose a prime modulus <b>p = ${p}</b> and generator <b>g = ${g}</b>. These values are public knowledge.`,
        math: `p = ${p} (prime), g = ${g} (base generator)`,
      },
      {
        num: 2,
        title: 'Choose Private Secrets',
        desc: `Alice secretly chooses <b>a = ${a}</b>. Bob secretly chooses <b>b = ${b}</b>. Neither shares their secret with anyone!`,
        math: `Alice: a = ${a} | Bob: b = ${b}`,
      },
      {
        num: 3,
        title: 'Compute & Exchange Public Values',
        desc: `Alice computes A and sends it to Bob. Bob computes B and sends it to Alice.`,
        math: `A = ${g}^${a} mod ${p} = <strong>${res.A}</strong><br>B = ${g}^${b} mod ${p} = <strong>${res.B}</strong>`,
      },
      {
        num: 4,
        title: 'Compute Identical Shared Secret',
        desc: `Both raise the received public value to their private secret. They arrive at the exact same key!`,
        math: `Alice: Bᵃ mod p = ${res.B}^${a} mod ${p} = <strong>${res.sharedFromAlice}</strong><br>Bob: Aᵇ mod p = ${res.A}^${b} mod ${p} = <strong>${res.sharedFromBob}</strong>`,
      },
    ];

    stepFlow.innerHTML = stepsData
      .map((s) => {
        const isActive = s.num === currentStep;
        const isCompleted = s.num < currentStep;
        return `
          <div class="step-card ${isActive ? 'step-card--active' : ''} ${isCompleted ? 'step-card--completed' : ''}">
            <div class="step-card-header">
              <span class="step-number">${isCompleted ? '✓' : s.num}</span>
              <span class="step-title">${s.title}</span>
            </div>
            <div class="step-body">${s.desc}</div>
            <div class="math-formula">${s.math}</div>
          </div>
        `;
      })
      .join('');

    // 3. Outcome Banner
    if (keyDone) {
      outcomeView.innerHTML = `
        <div class="outcome-banner outcome-banner--success">
          <div class="outcome-info">
            <span class="outcome-icon">🎉</span>
            <div>
              <div class="outcome-title">Key Exchange Successful! Both Generated Secret Key = ${res.sharedFromAlice}</div>
              <div class="outcome-desc">
                Mathematical proof: <code>(gᵇ)ᵃ mod p = gᵃᵇ mod p = (gᵃ)ᵇ mod p</code>.
                Alice and Bob can now encrypt messages securely using this shared key!
              </div>
            </div>
          </div>
          <div class="outcome-key-chips">
            <div class="key-chip">
              <span class="key-chip-label">Alice's Secret Key</span>
              <span class="key-chip-val" style="color:var(--ok)">K = ${res.sharedFromAlice}</span>
            </div>
            <div class="key-chip">
              <span class="key-chip-label">Bob's Secret Key</span>
              <span class="key-chip-val" style="color:var(--ok)">K = ${res.sharedFromBob}</span>
            </div>
          </div>
        </div>
      `;
    } else {
      outcomeView.innerHTML = '';
    }
  }

  // Event Listeners
  playBtn.addEventListener('click', toggleAutoPlay);
  resetBtn.addEventListener('click', () => {
    stopAutoPlay();
    currentStep = 1;
    updateUI();
  });
  prevBtn.addEventListener('click', () => {
    stopAutoPlay();
    if (currentStep > 1) {
      currentStep--;
      updateUI();
    }
  });
  nextBtn.addEventListener('click', () => {
    stopAutoPlay();
    if (currentStep < TOTAL_STEPS) {
      currentStep++;
      updateUI();
    }
  });

  [inP, inG, inA, inB].forEach((inp) => {
    inp.addEventListener('input', () => {
      stopAutoPlay();
      updateUI();
    });
  });

  updateUI();
  return section;
}

/* ==========================================================================
   SECTION 2: MAN-IN-THE-MIDDLE (MITM) ATTACK DEMONSTRATION
   ========================================================================== */

function renderMitmSection(): HTMLElement {
  const section = el('section', 'lab-section');
  section.id = 'mitm-section';

  // Parameters
  const p = 23n;
  const g = 5n;
  const a = 6n;
  const b = 15n;
  // Eve's private choices
  const e1 = 4n; // Eve facing Alice
  const e2 = 7n; // Eve facing Bob

  let currentStep = 1;
  const TOTAL_STEPS = 5;
  let timer: number | null = null;

  section.innerHTML = `
    <div class="section-tag" style="color:var(--alarm)">Section 2 · Attack Demonstration</div>
    <h2>2. Man-in-the-Middle (MITM) Attack Demonstration</h2>
    <p class="section-intro">
      <b>The Fatal Flaw:</b> Plain Diffie-Hellman does <b>not authenticate</b> who sent a public value.
      If an active attacker named <b>Eve</b> can intercept and modify messages on the wire, she can sit in between,
      cut the connection, and run two independent key exchanges — one with Alice and one with Bob!
    </p>

    <div class="controls-bar">
      <div class="btn-group">
        <button class="btn btn-danger" id="mitm-play-btn" type="button">▶ Start Attack Simulation</button>
        <button class="btn btn-ghost" id="mitm-reset-btn" type="button">↺ Reset</button>
      </div>

      <div class="stepper-nav">
        <button class="btn btn-ghost" id="mitm-prev-btn" type="button" title="Previous step">◀ Prev</button>
        <span class="stepper-counter" id="mitm-step-counter">Step 1 of 5</span>
        <button class="btn btn-ghost" id="mitm-next-btn" type="button" title="Next step">Next ▶</button>
      </div>

      <div style="font-size:0.84rem; color:var(--ink-soft); display:flex; align-items:center; gap:8px">
        <span>Attacker: <b>Eve</b> (e₁ = 4, e₂ = 7)</span>
      </div>
    </div>

    <!-- 3-Party Visual Interception Diagram -->
    <div class="visual-network" id="mitm-network-view"></div>

    <!-- Step Flow Cards -->
    <div class="step-flow" id="mitm-step-flow"></div>

    <!-- Alarm Outcome Banner -->
    <div id="mitm-outcome-view"></div>

    <!-- Live Interactive Message Interception Box -->
    <div class="message-box">
      <div class="message-box-header">
        <span style="font-size:1.4rem">🦹</span>
        <div>
          <h3>Live Demonstration: How Eve Reads &amp; Modifies Messages</h3>
          <p style="margin:2px 0 0; color:var(--ink-soft); font-size:0.84rem">
            Because Alice and Bob share separate keys with Eve, every message is secretly decrypted by Eve, altered, and re-encrypted.
          </p>
        </div>
      </div>

      <div class="message-inputs-grid">
        <div class="msg-field">
          <label for="alice-msg-in">👩 Alice's Message (Sent to "Bob"):</label>
          <input id="alice-msg-in" type="text" value="Meet me at the cafe at 5 PM">
        </div>
        <div class="msg-field">
          <label for="eve-msg-in">🦹 Eve Modifies It To:</label>
          <input id="eve-msg-in" type="text" value="Meet Eve at the bank and bring $5,000">
        </div>
        <button class="btn btn-danger" id="msg-relay-btn" type="button">Intercept &amp; Relay ▶</button>
      </div>

      <div class="msg-results-flow" id="msg-results-view">
        <span style="color:var(--ink-soft); font-size:0.86rem">Click "Intercept &amp; Relay ▶" to watch Eve intercept the encrypted message.</span>
      </div>
    </div>
  `;

  const playBtn = section.querySelector<HTMLButtonElement>('#mitm-play-btn')!;
  const resetBtn = section.querySelector<HTMLButtonElement>('#mitm-reset-btn')!;
  const prevBtn = section.querySelector<HTMLButtonElement>('#mitm-prev-btn')!;
  const nextBtn = section.querySelector<HTMLButtonElement>('#mitm-next-btn')!;
  const counterSpan = section.querySelector<HTMLSpanElement>('#mitm-step-counter')!;

  const networkView = section.querySelector<HTMLDivElement>('#mitm-network-view')!;
  const stepFlow = section.querySelector<HTMLDivElement>('#mitm-step-flow')!;
  const outcomeView = section.querySelector<HTMLDivElement>('#mitm-outcome-view')!;

  const aliceMsgIn = section.querySelector<HTMLInputElement>('#alice-msg-in')!;
  const eveMsgIn = section.querySelector<HTMLInputElement>('#eve-msg-in')!;
  const relayBtn = section.querySelector<HTMLButtonElement>('#msg-relay-btn')!;
  const msgResultsView = section.querySelector<HTMLDivElement>('#msg-results-view')!;

  function stopAutoPlay(): void {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
      playBtn.textContent = '▶ Start Attack Simulation';
      playBtn.classList.remove('btn-primary');
      playBtn.classList.add('btn-danger');
    }
  }

  function toggleAutoPlay(): void {
    if (timer !== null) {
      stopAutoPlay();
    } else {
      if (currentStep >= TOTAL_STEPS) currentStep = 1;
      playBtn.textContent = '⏸ Pause';
      playBtn.classList.remove('btn-danger');
      playBtn.classList.add('btn-primary');
      updateUI();
      timer = window.setInterval(() => {
        if (currentStep < TOTAL_STEPS) {
          currentStep++;
          updateUI();
        } else {
          stopAutoPlay();
        }
      }, 1800);
    }
  }

  function updateUI(): void {
    const res = mitm(p, g, a, b, e1, e2);

    counterSpan.textContent = `Step ${currentStep} of ${TOTAL_STEPS}`;
    prevBtn.disabled = currentStep <= 1;
    nextBtn.disabled = currentStep >= TOTAL_STEPS;

    const aliceIntercepted = currentStep >= 1;
    const eveToAliceSent = currentStep >= 2;
    const bobIntercepted = currentStep >= 3;
    const eveToBobSent = currentStep >= 4;
    const keysDone = currentStep >= 5;

    // 1. Three-Party Visual Diagram
    networkView.innerHTML = `
      <div class="parties-container parties-container--mitm">
        <!-- Alice Card -->
        <div class="party-card party-card--alice">
          <div class="party-header">
            <div class="party-identity">
              <span class="party-avatar">👩</span>
              <span class="party-name">Alice</span>
            </div>
            <span class="party-role party-role--user">Thinks: "Talking to Bob"</span>
          </div>
          <div class="party-data">
            <div class="data-row">
              <span class="data-label">Sends public A:</span>
              <span class="data-val data-val--public">${res.A}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Receives from wire:</span>
              <span class="data-val data-val--public">${eveToAliceSent ? `${res.M1} (Eve's)` : '…'}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Alice's Derived Key:</span>
              <span class="data-val ${keysDone ? 'data-val--key-alarm' : ''}">${keysDone ? `K = ${res.aliceKey}` : '…'}</span>
            </div>
          </div>
        </div>

        <!-- Cut Wire 1: Alice to Eve -->
        <div class="wire-col">
          <div class="cut-indicator">
            <span class="cut-scissors">✂️</span>
            <span>Wire Intercepted</span>
          </div>
          <div class="wire-line">
            <div class="wire-track wire-track--cut"></div>
            ${
              aliceIntercepted
                ? `<span class="wire-packet wire-packet--intercepted">A = ${res.A} (Trapped!)</span>`
                : ''
            }
          </div>
          <div class="wire-line">
            <div class="wire-track"></div>
            ${
              eveToAliceSent
                ? `<span class="wire-packet wire-packet--purple">⇠ E₁ = ${res.M1} (Fake Bob)</span>`
                : ''
            }
          </div>
        </div>

        <!-- Eve Card (Attacker in Middle) -->
        <div class="party-card party-card--eve">
          <div class="party-header">
            <div class="party-identity">
              <span class="party-avatar">🦹</span>
              <span class="party-name" style="color:var(--eve)">Eve (Attacker)</span>
            </div>
            <span class="party-role party-role--attacker">Man-in-the-Middle</span>
          </div>
          <div class="party-data">
            <div class="data-row">
              <span class="data-label">Intercepted values:</span>
              <span class="data-val">A = ${res.A}, B = ${res.B}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Substituted values:</span>
              <span class="data-val">E₁ = ${res.M1}, E₂ = ${res.M2}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Eve's Key with Alice:</span>
              <span class="data-val data-val--key-alarm">${keysDone ? `K₁ = ${res.malloryKeyWithAlice}` : '…'}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Eve's Key with Bob:</span>
              <span class="data-val data-val--key-alarm">${keysDone ? `K₂ = ${res.malloryKeyWithBob}` : '…'}</span>
            </div>
          </div>
        </div>

        <!-- Cut Wire 2: Eve to Bob -->
        <div class="wire-col">
          <div class="cut-indicator">
            <span class="cut-scissors">✂️</span>
            <span>Wire Intercepted</span>
          </div>
          <div class="wire-line">
            <div class="wire-track wire-track--cut"></div>
            ${
              bobIntercepted
                ? `<span class="wire-packet wire-packet--intercepted">B = ${res.B} (Trapped!)</span>`
                : ''
            }
          </div>
          <div class="wire-line">
            <div class="wire-track"></div>
            ${
              eveToBobSent
                ? `<span class="wire-packet wire-packet--purple">E₂ = ${res.M2} (Fake Alice) ➔</span>`
                : ''
            }
          </div>
        </div>

        <!-- Bob Card -->
        <div class="party-card party-card--bob">
          <div class="party-header">
            <div class="party-identity">
              <span class="party-avatar">🧑</span>
              <span class="party-name">Bob</span>
            </div>
            <span class="party-role party-role--user">Thinks: "Talking to Alice"</span>
          </div>
          <div class="party-data">
            <div class="data-row">
              <span class="data-label">Sends public B:</span>
              <span class="data-val data-val--public">${res.B}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Receives from wire:</span>
              <span class="data-val data-val--public">${eveToBobSent ? `${res.M2} (Eve's)` : '…'}</span>
            </div>
            <div class="data-row">
              <span class="data-label">Bob's Derived Key:</span>
              <span class="data-val ${keysDone ? 'data-val--key-alarm' : ''}">${keysDone ? `K = ${res.bobKey}` : '…'}</span>
            </div>
          </div>
        </div>
      </div>
    `;

    // 2. Step Flow Cards
    const stepsData = [
      {
        num: 1,
        title: 'Alice Sends A (Intercepted!)',
        desc: `Alice calculates <b>A = 5⁶ mod 23 = ${res.A}</b> and sends it toward Bob. <b>Eve intercepts it</b> — Bob never sees it!`,
        math: `Alice ➔ [Intercepted by Eve: A = ${res.A}]`,
      },
      {
        num: 2,
        title: 'Eve Spoofs Bob to Alice',
        desc: `Eve sends her own calculated value <b>E₁ = 5⁴ mod 23 = ${res.M1}</b> to Alice, claiming she is Bob.`,
        math: `Eve ➔ Alice: E₁ = ${res.M1} (Alice thinks this is B!)`,
      },
      {
        num: 3,
        title: 'Bob Sends B (Intercepted!)',
        desc: `Bob calculates <b>B = 5¹⁵ mod 23 = ${res.B}</b> and sends it toward Alice. <b>Eve intercepts it</b> too!`,
        math: `Bob ➔ [Intercepted by Eve: B = ${res.B}]`,
      },
      {
        num: 4,
        title: 'Eve Spoofs Alice to Bob',
        desc: `Eve sends her own calculated value <b>E₂ = 5⁷ mod 23 = ${res.M2}</b> to Bob, claiming she is Alice.`,
        math: `Eve ➔ Bob: E₂ = ${res.M2} (Bob thinks this is A!)`,
      },
      {
        num: 5,
        title: 'Two Separate Keys Formed!',
        desc: `Alice and Eve agree on Key <b>${res.aliceKey}</b>. Bob and Eve agree on Key <b>${res.bobKey}</b>. Alice and Bob have NO shared key!`,
        math: `Alice Key = ${res.M1}⁶ mod 23 = <strong>${res.aliceKey}</strong><br>Bob Key = ${res.M2}¹⁵ mod 23 = <strong>${res.bobKey}</strong>`,
      },
    ];

    stepFlow.innerHTML = stepsData
      .map((s) => {
        const isActive = s.num === currentStep;
        const isCompleted = s.num < currentStep;
        return `
          <div class="step-card ${isActive ? 'step-card--active' : ''} ${isCompleted ? 'step-card--completed' : ''}">
            <div class="step-card-header">
              <span class="step-number" style="${s.num >= 1 && s.num <= 4 ? 'background:var(--alarm)' : ''}">${isCompleted ? '✓' : s.num}</span>
              <span class="step-title">${s.title}</span>
            </div>
            <div class="step-body">${s.desc}</div>
            <div class="math-formula">${s.math}</div>
          </div>
        `;
      })
      .join('');

    // 3. Outcome Banner
    if (keysDone) {
      outcomeView.innerHTML = `
        <div class="outcome-banner outcome-banner--alarm">
          <div class="outcome-info">
            <span class="outcome-icon">🚨</span>
            <div>
              <div class="outcome-title">Security Breached! Alice's Key (${res.aliceKey}) ≠ Bob's Key (${res.bobKey})</div>
              <div class="outcome-desc">
                Eve successfully split the connection! Alice mistakenly thinks she is talking to Bob. Bob mistakenly thinks he is talking to Alice.
                Eve holds the keys to both sides and can decrypt, inspect, and modify all messages.
              </div>
            </div>
          </div>
          <div class="outcome-key-chips">
            <div class="key-chip">
              <span class="key-chip-label">👩 Alice's Key (Shared with Eve)</span>
              <span class="key-chip-val" style="color:var(--alarm)">K₁ = ${res.aliceKey}</span>
            </div>
            <div class="key-chip">
              <span class="key-chip-label">🧑 Bob's Key (Shared with Eve)</span>
              <span class="key-chip-val" style="color:var(--alarm)">K₂ = ${res.bobKey}</span>
            </div>
          </div>
        </div>
      `;
    } else {
      outcomeView.innerHTML = '';
    }
  }

  // Interactive Message Relay Handler
  async function handleRelay(): Promise<void> {
    const res = mitm(p, g, a, b, e1, e2);
    relayBtn.disabled = true;
    msgResultsView.innerHTML = `<span style="color:var(--blue-light)">Encrypting and intercepting through Eve…</span>`;

    try {
      const outcome = await interceptMessage(
        res.aliceKey,
        res.bobKey,
        aliceMsgIn.value,
        eveMsgIn.value,
      );

      msgResultsView.innerHTML = `
        <div class="msg-step-item">
          <span class="msg-step-badge">1. Alice Encrypts</span>
          <span>Alice encrypts <b>"${escapeHtml(aliceMsgIn.value)}"</b> using Alice-Eve Key <b>(${res.aliceKey})</b> and sends it.</span>
        </div>
        <div class="msg-step-item" style="color:var(--eve)">
          <span class="msg-step-badge" style="background:var(--eve-bg); color:var(--eve)">2. Eve Intercepts</span>
          <span>Eve decrypts with Key <b>(${res.aliceKey})</b> and reads: <i>"${escapeHtml(outcome.malloryReads ?? '')}"</i>.</span>
        </div>
        <div class="msg-step-item" style="color:var(--alarm)">
          <span class="msg-step-badge" style="background:var(--alarm-bg); color:var(--alarm)">3. Eve Tampers</span>
          <span>Eve alters the text to: <b>"${escapeHtml(outcome.forwarded)}"</b> and re-encrypts using Bob-Eve Key <b>(${res.bobKey})</b>.</span>
        </div>
        <div class="msg-step-item">
          <span class="msg-step-badge">4. Bob Decrypts</span>
          <span>Bob decrypts with Key <b>(${res.bobKey})</b> and reads: <b style="color:#ffffff">"${escapeHtml(outcome.bobReads ?? '')}"</b>!</span>
        </div>
        <div style="margin-top:6px; padding:10px 14px; border-radius:8px; background:rgba(244,63,94,0.15); border:1px solid rgba(244,63,94,0.3); font-size:0.84rem; color:#fecdd3">
          <b>The Takeaway:</b> Bob believes Alice wrote this message! If Bob had tried to decrypt Alice's original ciphertext directly with his key, it would completely fail because they do not share a key.
        </div>
      `;
    } catch {
      msgResultsView.innerHTML = `<span style="color:var(--alarm)">Failed to relay message.</span>`;
    } finally {
      relayBtn.disabled = false;
    }
  }

  // Event Listeners
  playBtn.addEventListener('click', toggleAutoPlay);
  resetBtn.addEventListener('click', () => {
    stopAutoPlay();
    currentStep = 1;
    updateUI();
  });
  prevBtn.addEventListener('click', () => {
    stopAutoPlay();
    if (currentStep > 1) {
      currentStep--;
      updateUI();
    }
  });
  nextBtn.addEventListener('click', () => {
    stopAutoPlay();
    if (currentStep < TOTAL_STEPS) {
      currentStep++;
      updateUI();
    }
  });
  relayBtn.addEventListener('click', () => void handleRelay());

  updateUI();
  return section;
}

/* ==========================================================================
   SECTION 3: COMPARISON: NORMAL DH VS. MITM ATTACK
   ========================================================================== */

function renderComparisonSection(): HTMLElement {
  const section = el('section', 'lab-section');
  section.id = 'comparison-section';

  section.innerHTML = `
    <div class="section-tag" style="color:var(--blue-light)">Section 3 · Comparison</div>
    <h2>3. Comparison: Normal DH vs. MITM Attack</h2>
    <p class="section-intro">
      Compare how standard Diffie-Hellman behaves when communication is direct versus when an active attacker intercepts the channel.
    </p>

    <!-- Side-by-Side Comparison Cards -->
    <div class="comparison-grid">
      <!-- Card 1: Normal Diffie-Hellman -->
      <div class="compare-card compare-card--normal">
        <div class="compare-card-header">
          <span class="compare-card-title">🛡️ Normal Diffie-Hellman</span>
          <span class="compare-status-badge badge--ok">Secure</span>
        </div>
        <ul class="compare-list">
          <li>
            <span>🔗</span>
            <div><strong>Direct Channel:</strong> Alice and Bob communicate directly without modification.</div>
          </li>
          <li>
            <span>🔑</span>
            <div><strong>1 Shared Secret Key:</strong> Both parties calculate the exact same key (e.g., K = 2).</div>
          </li>
          <li>
            <span>👂</span>
            <div><strong>Passive Eavesdropper:</strong> An eavesdropper can hear everything, but cannot calculate the secret key.</div>
          </li>
          <li>
            <span>✅</span>
            <div><strong>Privacy:</strong> End-to-end confidential communication is achieved.</div>
          </li>
        </ul>
      </div>

      <!-- Card 2: MITM Attack -->
      <div class="compare-card compare-card--mitm">
        <div class="compare-card-header">
          <span class="compare-card-title">🦹 Under MITM Attack</span>
          <span class="compare-status-badge badge--danger">Compromised</span>
        </div>
        <ul class="compare-list">
          <li>
            <span>✂️</span>
            <div><strong>Intercepted Channel:</strong> Eve cuts the line and impersonates each party to the other.</div>
          </li>
          <li>
            <span>🔑</span>
            <div><strong>2 Separate Keys:</strong> Alice shares K₁ = 9 with Eve; Bob shares K₂ = 14 with Eve.</div>
          </li>
          <li>
            <span>🕵️</span>
            <div><strong>Active Manipulator:</strong> Eve decrypts, reads, alters, and re-encrypts all messages.</div>
          </li>
          <li>
            <span>🚨</span>
            <div><strong>False Security:</strong> Alice and Bob mistakenly believe they are talking securely.</div>
          </li>
        </ul>
      </div>
    </div>
  `;

  return section;
}

/* ==========================================================================
   MOUNT APPLICATION
   ========================================================================== */

export function mountApp(root: HTMLElement): void {
  const shell = el('div', 'page-shell');
  shell.append(
    renderHero(),
    renderDhSection(),
    renderMitmSection(),
    renderComparisonSection(),
  );
  root.replaceChildren(shell);
}
