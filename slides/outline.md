# rlint — 3-minute pitch outline

Owner: VG. Source of truth for content: [rlint.md](../rlint.md) §9, [PLAN.md](../PLAN.md) §9.
Say the recall number **twice**. Backup video recorded at 15:00 regardless of live-demo state.

---

## Slide 1 — Problem (0:00–0:30)

- Agents can write RL environments now.
- An agent-written reward gets gamed by the policy trained against it.
- Reward goes up, capability does not — **silently**.
- rlint: a linter for agent-generated RL environments. Attack it before you spend GPU
  hours training against it.

## Slide 2 — Generate (0:30–1:00)

- `rlint gen "<task description>"` → environment appears.
- Live: run against a generated env, not just a fixture.

## Slide 3 — Attack (1:00–1:45)

- `rlint attack` → 20+ Daytona sandboxes in parallel. Wall-clock number on screen.
- Every attacker scores reward 1.0.
- *"This environment would have produced a perfect training curve and a useless model."*

## Slide 4 — Detect (1:45–2:15)

- Detection table (rlint.md §5.8 format).
- **Recall number** — say it here (first time).
- Braintrust experiment view: detectors as scorers, attacker suite as dataset.

## Slide 5 — Patch (2:15–2:40)

- `rlint patch` → hardened EnvSpec: out-of-band grading, tightened `solution_paths`,
  `network=false`, expanded held-out set.
- Re-run → exploits now fail. Braintrust pre/post experiment diff.
- Say the **recall number again** (second time), framed against the before/after table.

## Slide 6 — Limits and roadmap (2:40–3:00)

State the blind spots out loud — naming them is the credibility move in front of a
Braintrust eval engineer judge:

- **H1** — semantic exploits against LLM-judge rewards (length bias, confident tone,
  sycophancy). Different detection problem.
- **H2** — spec error: environment faithfully implements a reward the user didn't mean.
  Not a hack; only a human catches it.
- **H3** — selection on the detector: filtering only on "our detector didn't flag it"
  selects for exploits we can't see. Mitigated by a human-audited sample and by reporting
  detector recall against planted exploits.

Roadmap: Fireworks RFT on a verified environment.

---

## Speaker notes

- The one deliverable: *N exploit classes attempted across M environments; K detected;
  here are the ones that got through and why.*
- The sentence for the Braintrust judge: *"our detectors are Braintrust scorers, our
  attacker suite is a Braintrust dataset, and hardening an environment is a measurable
  experiment diff."*
- If the recall number is bad (e.g. 4/8), report it honestly with named gaps — a real
  number beats an unmeasured claim.
