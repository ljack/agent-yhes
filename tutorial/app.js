(() => {
  'use strict';
  const M = window.YhesTutorial;
  const $ = id => document.getElementById(id);
  let state = M.create(), playing = false, timer = null, motion = null, selected = null;
  let approvalReturnTarget = null;
  const extra = { alice: [], bob: [] };
  const reduceQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const iconPaths = {
    harness: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01M7 13l2 2-2 2m5 0h5"/>',
    agent: '<rect x="5" y="6" width="14" height="14" rx="3"/><path d="M12 3v3M2 11h3m14 0h3M9 12h.01M15 12h.01M9 16h6"/>',
    llm: '<circle cx="12" cy="12" r="3"/><circle cx="4" cy="5" r="2"/><circle cx="20" cy="5" r="2"/><circle cx="4" cy="19" r="2"/><circle cx="20" cy="19" r="2"/><path d="M6 6.5l4 3m4 0 4-3M6 17.5l4-3m4 0 4 3"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
    fingerprint: '<path d="M4 10a8 8 0 0 1 16 0v3M7 20c2-3 1-6 1-10a4 4 0 0 1 8 0c0 5 1 7 2 9M4 14c0 3-1 4-1 4m9-8v6c0 3-1 5-2 6m5-4 1 3M7 5c3-3 7-3 10 0"/>',
    git: '<circle cx="7" cy="5" r="2"/><circle cx="7" cy="19" r="2"/><circle cx="18" cy="7" r="2"/><path d="M7 7v10m0-4h4c4 0 7-1 7-4"/>',
    repo: '<path d="M5 3h14v18H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zm0 0v14h14M3 18h16M8 7h7m-7 4h5"/>',
    broadcast: '<circle cx="12" cy="12" r="2"/><path d="M7.5 7.5a6.4 6.4 0 0 0 0 9m9-9a6.4 6.4 0 0 1 0 9M4.5 4.5a10.6 10.6 0 0 0 0 15m15-15a10.6 10.6 0 0 1 0 15"/>'
  };
  document.querySelectorAll('[data-icon]').forEach(el => {
    el.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${iconPaths[el.dataset.icon] || ''}</svg>`;
  });

  let savedTheme = null;
  try { savedTheme = localStorage.getItem('yhes-tutorial-theme'); } catch { /* optional preference */ }
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    $('theme-toggle').textContent = theme === 'dark' ? 'Light' : 'Dark';
    $('theme-toggle').setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
    try { localStorage.setItem('yhes-tutorial-theme', theme); } catch { /* local files may restrict storage */ }
  }
  setTheme(savedTheme === 'dark' ? 'dark' : 'light');
  $('theme-toggle').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));

  M.chapters.forEach((chapter, i) => {
    const button = document.createElement('button'); button.className = 'chapter'; button.dataset.chapter = chapter.id;
    const index = document.createElement('span'); index.className = 'chapter-index'; index.textContent = String(i + 1);
    const label = document.createElement('span'); label.textContent = chapter.title;
    button.append(index, label); button.addEventListener('click', () => choose(chapter.id));
    $('chapters').append(button);
  });

  function stop() {
    playing = false; clearTimeout(timer); timer = null;
    cancelAnimationFrame(motion); motion = null; $('traveller').style.opacity = '0';
  }
  function announce(message) { $('announcement').textContent = message; }
  function clearExtras() {
    for (const side of ['alice', 'bob']) { extra[side] = []; $(`${side}-error`).textContent = ''; }
  }
  function syncInputs() {
    const cmds = M.commands(state);
    $('alice-command').value = cmds.alice;
    $('bob-command').value = cmds.bob;
  }
  function choose(chapter, side, text = '') {
    const keepOffline = chapter === 'message' && state.chapter === 'message' ? state.offline : false;
    stop(); closeInspector(); clearExtras();
    state = M.create(chapter, side, text, keepOffline);
    $('why').open = false;
    syncInputs();
    render(true);
  }
  function showHistory(side) {
    const output = $(`${side}-output`);
    output.replaceChildren();
    const entries = [...M.history(state, side), ...extra[side]];
    if (!entries.length) {
      const blank = document.createElement('p'); blank.className = 'terminal-line empty';
      blank.textContent = `Waiting for ${M.names[side]}’s step.`; output.append(blank);
    }
    for (const row of entries) {
      const line = document.createElement('p'); line.className = `terminal-line ${row.kind}`; line.textContent = row.text;
      output.append(line);
    }
    output.scrollTop = output.scrollHeight;
  }
  function render(animate = false) {
    const current = M.current(state), frames = M.frames(state), last = state.index === frames.length - 1;
    document.querySelectorAll('[data-chapter]').forEach(el => {
      if (el.dataset.chapter === state.chapter) el.setAttribute('aria-current', 'step'); else el.removeAttribute('aria-current');
    });
    document.querySelectorAll('.object,.terminal').forEach(el => {
      el.classList.toggle('is-active', [...current.route, ...(current.active || [])].includes(el.id));
    });
    $('step-count').textContent = `${state.index + 1} / ${frames.length}`;
    $('step-title').textContent = current.title;
    $('step-text').textContent = current.text;
    $('why-text').textContent = current.why;
    $('packet-label').textContent = current.sealed ? 'Encrypted payload' : 'In this step';
    $('packet-content').textContent = current.packet || current.status;
    $('packet').classList.toggle('sealed', !!current.sealed);
    const senderSide = state.chapter === 'recovery' ? (state.side === 'alice' ? 'bob' : 'alice') : state.side;
    for (const side of ['alice', 'bob']) {
      const caption = $(side + '-crypto').querySelector('small');
      caption.textContent = state.chapter === 'connect' ? 'Sign / verify' : side === senderSide ? 'Sign / encrypt' : 'Decrypt / verify';
    }
    $('repo-state').textContent = current.archived ? 'Signed record committed' : state.chapter === 'connect' ? current.status : 'Public identities + sealed records';
    const inMessage = state.chapter === 'message';
    const offline = !!current.blockedBroker || (inMessage && state.offline);
    $('jetstream').classList.toggle('offline', offline);
    $('broker-state').textContent = current.blockedBroker && !inMessage
      ? 'Broker unreachable'
      : offline
        ? 'Broker paused'
        : current.status === 'Broker available'
          ? 'Back online · notice retried'
          : current.archived
            ? 'Notice after Git confirmation'
            : 'Wakes active listeners';
    $('broker-toggle').hidden = !inMessage;
    $('broker-toggle').disabled = !inMessage;
    $('broker-toggle').textContent = inMessage && state.offline ? 'Resume broker' : 'Pause broker';
    $('previous').disabled = state.index === 0;
    $('play').textContent = playing ? 'Pause' : last ? 'Replay flow' : 'Play flow';
    $('play').disabled = M.needsApproval(state);
    $('next').textContent = M.needsApproval(state) ? 'Review statement' : last ? state.chapter === 'recovery' ? 'Start again' : 'Next chapter →' : 'Next step →';
    const sides = new Set(current.route.map(id => id.startsWith('alice-') ? 'Alice' : id.startsWith('bob-') ? 'Bob' : 'Shared'));
    const actor = sides.size === 1 ? [...sides][0] : current.route[0]?.startsWith('alice-') ? 'Alice →' : current.route[0]?.startsWith('bob-') ? 'Bob →' : 'Shared';
    $('mobile-count').textContent = `${state.index + 1}/${frames.length} · ${actor}`;
    $('mobile-title').textContent = current.title;
    $('mobile-back').disabled = $('previous').disabled;
    $('mobile-play').disabled = $('play').disabled;
    $('mobile-play').textContent = $('play').textContent;
    $('mobile-next').textContent = $('next').textContent;
    $('progress-track').replaceChildren(...frames.map((_, i) => {
      const span = document.createElement('span'); span.className = `progress-segment${i <= state.index ? ' done' : ''}`; return span;
    }));
    showHistory('alice'); showHistory('bob');
    announce(`Step ${state.index + 1} of ${frames.length}. ${current.title}. ${current.text}`);
    requestAnimationFrame(() => drawWires(animate));
  }
  function step() {
    if (M.needsApproval(state)) { stop(); render(); return; }
    const before = state.index;
    state = M.next(state);
    if (before === state.index || state.index === M.frames(state).length - 1 || M.needsApproval(state)) playing = false;
    render(true);
    if (playing) timer = setTimeout(step, 3100);
  }
  function play() {
    if (playing) { stop(); render(); return; }
    if (M.needsApproval(state)) return;
    if (state.index === M.frames(state).length - 1) {
      state = M.create(state.chapter, state.side, state.text, state.offline); clearExtras();
    }
    playing = true; render(true); timer = setTimeout(step, 3100);
  }
  $('play').addEventListener('click', play);
  $('mobile-back').addEventListener('click', () => $('previous').click());
  $('mobile-play').addEventListener('click', () => $('play').click());
  $('mobile-next').addEventListener('click', () => $('next').click());
  $('previous').addEventListener('click', () => { stop(); state = M.previous(state); render(true); });
  $('replay').addEventListener('click', () => {
    stop(); clearExtras();
    state = M.create(state.chapter, state.side, state.text, state.offline);
    syncInputs();
    render(true);
  });
  $('next').addEventListener('click', () => {
    stop();
    if (M.needsApproval(state)) { openApproval(); return; }
    if (state.index === M.frames(state).length - 1) {
      const index = M.chapters.findIndex(c => c.id === state.chapter);
      choose(M.chapters[(index + 1) % M.chapters.length].id); return;
    }
    state = M.next(state); render(true);
  });
  $('broker-toggle').addEventListener('click', () => {
    stop(); const offline = !state.offline;
    state = M.create('message', state.side, state.text, offline); clearExtras(); syncInputs(); render(true);
  });

  for (const side of ['alice', 'bob']) {
    $(`${side}-form`).addEventListener('submit', event => {
      event.preventDefault(); stop(); closeInspector();
      const result = M.parse($(`${side}-command`).value, side);
      if (result.error) { $(`${side}-error`).textContent = result.error; render(); announce(result.error); return; }
      $(`${side}-error`).textContent = '';
      if (result.help) {
        extra[side].push({ kind: 'result', text: 'Shortcuts: bootstrap · send "text" · say "text" · inbox' }); render(); return;
      }
      const keepOffline = result.state.chapter === 'message' && state.chapter === 'message' ? state.offline : false;
      clearExtras();
      state = { ...result.state, offline: keepOffline };
      $('why').open = false;
      syncInputs();
      playing = true; render(true); timer = setTimeout(step, 3100);
    });
  }
  document.querySelectorAll('[data-fill]').forEach(button => button.addEventListener('click', () => {
    const [side, command] = button.dataset.fill.split(':');
    const value = command === 'send'
      ? `send "${side === 'alice' ? 'Can you review the retry logic?' : 'I checked the retry behavior.'}"`
      : command === 'say'
        ? `say "${side === 'alice' ? 'I approve this direction.' : 'I agree with this proposal.'}"`
        : command;
    $(`${side}-command`).value = value; $(`${side}-command`).focus();
  }));

  function restoreFocus(target) {
    if (!target) return;
    const r = target.getBoundingClientRect();
    if (r.top < 0 || r.bottom > window.innerHeight) {
      target.scrollIntoView({ behavior: reduceQuery.matches ? 'instant' : 'smooth', block: 'nearest' });
    }
    target.focus();
  }
  function closeInspector() {
    $('inspector').hidden = true;
    if (selected) {
      selected.removeAttribute('data-selected');
      selected.setAttribute('aria-expanded', 'false');
    }
    selected = null;
    requestAnimationFrame(() => drawWires());
  }
  document.querySelectorAll('[data-object]').forEach(button => button.addEventListener('click', () => {
    if (selected === button && !$('inspector').hidden) {
      const back = selected;
      closeInspector();
      restoreFocus(back);
      return;
    }
    stop();
    const object = M.objects[button.dataset.object];
    if (selected) {
      selected.removeAttribute('data-selected');
      selected.setAttribute('aria-expanded', 'false');
    }
    selected = button;
    selected.setAttribute('data-selected', 'true');
    selected.setAttribute('aria-expanded', 'true');
    $('object-owner').textContent = button.dataset.side ? `${M.names[button.dataset.side]}’s side` : 'Shared infrastructure';
    $('object-title').textContent = object.title; $('object-job').textContent = object.job;
    $('object-detail').textContent = object.detail; $('object-why').textContent = object.why;
    $('inspector').hidden = false;
    render();
    const r = $('inspector').getBoundingClientRect();
    if (r.top < 0 || r.bottom > window.innerHeight) {
      $('inspector').scrollIntoView({ behavior: reduceQuery.matches ? 'instant' : 'smooth', block: 'nearest' });
    }
    $('inspector-close').focus();
  }));
  $('inspector-close').addEventListener('click', () => { const back = selected; closeInspector(); restoreFocus(back); });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !$('inspector').hidden && !$('approval-dialog').open) {
      const back = selected;
      closeInspector();
      restoreFocus(back);
    }
  });
  $('why').addEventListener('toggle', () => { if ($('why').open) { stop(); render(); } });

  function openApproval() {
    approvalReturnTarget = document.activeElement;
    extra[state.side] = [];
    $('approval-text').textContent = state.text;
    $('approval-author').textContent = M.names[state.side];
    $('approval-dialog').showModal(); $('approval-cancel').focus();
  }
  $('approval-confirm').addEventListener('click', () => {
    $('approval-dialog').close(); extra[state.side] = []; state = M.approve(state); render(true); restoreFocus(approvalReturnTarget || $('next'));
  });
  function cancelApproval() {
    $('approval-dialog').close();
    extra[state.side].push({ kind: 'result', text: 'Review cancelled · statement not signed.' });
    render(); restoreFocus(approvalReturnTarget || $('next'));
  }
  $('approval-cancel').addEventListener('click', cancelApproval);
  $('approval-dialog').addEventListener('cancel', event => { event.preventDefault(); cancelApproval(); });

  const narrow = window.matchMedia('(max-width: 780px)');
  let storyVisible = true, startVisible = false;
  function mobileControls() {
    const hide = !narrow.matches || storyVisible || (!$('getting-started').hidden && startVisible);
    $('mobile-playback').hidden = hide;
    document.body.classList.toggle('has-mobile-bar', !hide);
  }
  function showStart(show) {
    stop(); render(); closeInspector();
    $('getting-started').hidden = !show;
    $('start-toggle').setAttribute('aria-expanded', String(show));
    if (!show) startVisible = false;
    mobileControls();
    if (show) {
      $('getting-started').scrollIntoView({ behavior: reduceQuery.matches ? 'instant' : 'smooth', block: 'start' });
      const sr = $('getting-started').getBoundingClientRect();
      if (sr.top < window.innerHeight && sr.bottom > 0) { startVisible = true; mobileControls(); }
    } else {
      $('start-toggle').focus();
    }
  }
  $('start-toggle').addEventListener('click', () => showStart($('getting-started').hidden));
  $('start-close').addEventListener('click', () => showStart(false));
  document.querySelectorAll('[data-guide]').forEach(button => button.addEventListener('click', () => {
    const real = button.dataset.guide === 'real';
    $('simulation-guide').hidden = real; $('real-guide').hidden = !real;
    document.querySelectorAll('[data-guide]').forEach(b => { const active = b === button; b.classList.toggle('selected', active); b.setAttribute('aria-pressed', String(active)); });
  }));
  $('bootstrap-prompt').textContent = M.bootstrap;
  $('copy-prompt').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(M.bootstrap); $('copy-status').textContent = 'Copied. Paste it in each prepared project’s agent session.'; }
    catch {
      const range = document.createRange(); range.selectNodeContents($('bootstrap-prompt'));
      const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
      $('copy-status').textContent = 'The prompt is selected. Copy it with your usual keyboard shortcut.';
    }
  });

  const NS = 'http://www.w3.org/2000/svg';
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
  function roundedOrthogonal(rawPoints, radius = 6) {
    const pts = [];
    for (const pt of rawPoints) {
      const prev = pts[pts.length - 1];
      if (!prev || Math.hypot(pt[0] - prev[0], pt[1] - prev[1]) > 0.5) pts.push(pt);
    }
    if (pts.length < 2) return '';
    if (pts.length === 2) return `M ${pts[0][0]} ${pts[0][1]} L ${pts[1][0]} ${pts[1][1]}`;
    let d = `M ${pts[0][0]} ${pts[0][1]}`;
    for (let i = 1; i < pts.length - 1; i++) {
      const p0 = pts[i - 1], p1 = pts[i], p2 = pts[i + 1];
      const v1x = p1[0] - p0[0], v1y = p1[1] - p0[1], l1 = Math.hypot(v1x, v1y);
      const v2x = p2[0] - p1[0], v2y = p2[1] - p1[1], l2 = Math.hypot(v2x, v2y);
      const r = Math.min(radius, l1 / 2, l2 / 2);
      if (r < 1) { d += ` L ${p1[0]} ${p1[1]}`; continue; }
      const ax = p1[0] - (v1x / l1) * r, ay = p1[1] - (v1y / l1) * r;
      const bx = p1[0] + (v2x / l2) * r, by = p1[1] + (v2y / l2) * r;
      d += ` L ${ax} ${ay} Q ${p1[0]} ${p1[1]} ${bx} ${by}`;
    }
    const last = pts[pts.length - 1];
    return `${d} L ${last[0]} ${last[1]}`;
  }
  function drawWires(animate = false) {
    cancelAnimationFrame(motion); $('traveller').style.opacity = '0';
    const box = $('world').getBoundingClientRect();
    if (!box.width || !box.height) return;
    $('wires').setAttribute('viewBox', `0 0 ${box.width} ${box.height}`);
    $('wire-paths').replaceChildren();
    const route = M.current(state).route, paths = [];
    const coords = id => {
      const r = $(id).getBoundingClientRect();
      return { x: r.left - box.left, y: r.top - box.top, w: r.width, h: r.height, right: r.right - box.left, bottom: r.bottom - box.top, cx: r.left - box.left + r.width / 2, cy: r.top - box.top + r.height / 2 };
    };
    const sideOf = id => id.startsWith('alice-') ? 'alice' : id.startsWith('bob-') ? 'bob' : 'shared';
    const alleyY = side => (coords(`${side}-agent`).bottom + coords(`${side}-crypto`).y) / 2;
    const personBounds = side => ({ left: coords(`${side}-terminal`).x, right: coords(`${side}-terminal`).right });
    const innerCards = new Set(['alice-llm', 'alice-git', 'alice-terminal', 'alice-human', 'bob-llm', 'bob-git', 'bob-terminal', 'bob-human']);
    const pairCounts = new Map();
    for (let i = 0; i < route.length - 1; i++) {
      if (route[i] === route[i + 1]) continue;
      const key = [route[i], route[i + 1]].sort().join('|');
      pairCounts.set(key, (pairCounts.get(key) || 0) + 1);
    }
    const pairSeen = new Map();
    for (let i = 0; i < route.length - 1; i++) {
      const fromId = route[i], toId = route[i + 1];
      if (fromId === toId) continue;
      const key = [fromId, toId].sort().join('|');
      const totalPairs = pairCounts.get(key) || 1;
      const occurrence = pairSeen.get(key) || 0;
      pairSeen.set(key, occurrence + 1);
      const pairOffset = totalPairs > 1 ? clamp((occurrence - (totalPairs - 1) / 2) * 7, -5, 5) : 0;
      const a = coords(fromId), b = coords(toId);
      const fromSide = sideOf(fromId), toSide = sideOf(toId);
      let d = '';
      const biometricJump = (fromId.endsWith('-human') && toId.endsWith('-biometric')) || (fromId.endsWith('-biometric') && toId.endsWith('-human'));
      if (biometricJump && fromSide === toSide) {
        const bounds = personBounds(fromSide);
        const right = fromSide === 'bob';
        const gx = right ? Math.min(box.width - 5, bounds.right + 9) : Math.max(5, bounds.left - 9);
        const ax = right ? a.right : a.x, bx = right ? b.right : b.x;
        d = roundedOrthogonal([[ax, a.cy + pairOffset], [gx, a.cy + pairOffset], [gx, b.cy + pairOffset], [bx, b.cy + pairOffset]], 8);
      } else if (fromSide !== toSide && (fromSide === 'shared' || toSide === 'shared')) {
        const pSide = fromSide === 'shared' ? toSide : fromSide;
        const pId = fromSide === 'shared' ? toId : fromId;
        const sId = fromSide === 'shared' ? fromId : toId;
        const pRect = fromSide === 'shared' ? b : a;
        const sRect = fromSide === 'shared' ? a : b;
        const ym = alleyY(pSide) + pairOffset * 0.6;
        if (!narrow.matches) {
          const pIsLeft = pSide === 'alice';
          const sx = pIsLeft ? sRect.x : sRect.right;
          const pInner = pIsLeft ? personBounds('alice').right : personBounds('bob').left;
          if (innerCards.has(pId)) {
            const px = pIsLeft ? pRect.right : pRect.x;
            const sy = clamp(pRect.cy, sRect.y + 12, sRect.bottom - 12);
            const ax = fromSide === 'shared' ? sx : px, bx = fromSide === 'shared' ? px : sx;
            const ay = (fromSide === 'shared' ? sy : pRect.cy) + pairOffset;
            const by = (fromSide === 'shared' ? pRect.cy : sy) + pairOffset;
            const mid = (ax + bx) / 2;
            d = `M ${ax} ${ay} C ${mid} ${ay} ${mid} ${by} ${bx} ${by}`;
          } else {
            const cxGap = (sx + pInner) / 2;
            const sy = clamp(ym, sRect.y + 12, sRect.bottom - 12);
            const py = pRect.cy < ym ? pRect.bottom : pRect.y;
            const pts = [[sx, sy], [cxGap, sy], [cxGap, ym], [pRect.cx, ym], [pRect.cx, py]];
            if (fromSide !== 'shared') pts.reverse();
            d = roundedOrthogonal(pts, 6);
          }
        } else {
          const adjacentAliceGit = pId === 'alice-git' && sId === 'repository';
          if (adjacentAliceGit) {
            const sy = sRect.y, py = pRect.bottom, midY = (py + sy) / 2;
            const pts = [[sRect.cx + pairOffset, sy], [sRect.cx + pairOffset, midY], [pRect.cx + pairOffset, midY], [pRect.cx + pairOffset, py]];
            if (fromSide !== 'shared') pts.reverse();
            d = roundedOrthogonal(pts, 6);
          } else {
            const useRight = sId === 'jetstream';
            const gx = useRight ? box.width - 5 : 5;
            const sx = useRight ? sRect.right : sRect.x;
            const sy = sRect.cy + pairOffset;
            const py = pRect.cy < ym ? pRect.bottom : pRect.y;
            const pts = [[sx, sy], [gx, sy], [gx, ym], [pRect.cx, ym], [pRect.cx, py]];
            if (fromSide !== 'shared') pts.reverse();
            d = roundedOrthogonal(pts, 7);
          }
        }
      } else if (a.bottom <= b.y + 2 || b.bottom <= a.y + 2) {
        const goingDown = b.cy > a.cy;
        const ay = goingDown ? a.bottom : a.y, by = goingDown ? b.y : b.bottom;
        const axBase = fromId.endsWith('-terminal') ? clamp(b.cx, a.x + 18, a.right - 18) : a.cx;
        const bxBase = toId.endsWith('-terminal') ? clamp(a.cx, b.x + 18, b.right - 18) : b.cx;
        const ax = axBase + pairOffset, bx = bxBase + pairOffset;
        if (Math.abs(ax - bx) < 2) {
          d = `M ${ax} ${ay} L ${bx} ${by}`;
        } else {
          const midY = (ay + by) / 2 + pairOffset * 0.5;
          d = roundedOrthogonal([[ax, ay], [ax, midY], [bx, midY], [bx, by]], 5);
        }
      } else {
        const goingRight = b.cx > a.cx;
        const ax = goingRight ? a.right : a.x, bx = goingRight ? b.x : b.right;
        const ay = a.cy + pairOffset, by = b.cy + pairOffset;
        if (Math.abs(ay - by) < 2) {
          d = `M ${ax} ${ay} L ${bx} ${by}`;
        } else {
          const midX = (ax + bx) / 2;
          d = `M ${ax} ${ay} C ${midX} ${ay} ${midX} ${by} ${bx} ${by}`;
        }
      }
      const path = document.createElementNS(NS, 'path'); path.setAttribute('d', d);
      const isNotification = [fromId, toId].includes('jetstream');
      const type = [fromId, toId].some(id => id.endsWith('-llm')) ? 'reasoning' : isNotification ? 'notification' : '';
      path.setAttribute('class', `wire${type ? ` ${type}` : ''}`);
      if (isNotification) path.setAttribute('marker-end', 'url(#arrow-accent)');
      $('wire-paths').append(path); paths.push(path);
    }
    if (!animate || reduceQuery.matches || !paths.length) return;
    const lengths = paths.map(p => p.getTotalLength()), total = lengths.reduce((a, b) => a + b, 0), start = performance.now();
    if (total <= 0) return;
    const duration = Math.min(2300, Math.max(900, total * 2));
    const tick = time => {
      const fraction = Math.min(1, (time - start) / duration); let distance = fraction * total, index = 0;
      while (index < paths.length - 1 && distance > lengths[index]) distance -= lengths[index++];
      const point = paths[index].getPointAtLength(distance);
      $('traveller').setAttribute('cx', point.x); $('traveller').setAttribute('cy', point.y);
      $('traveller').style.opacity = fraction < 1 ? '1' : '0';
      if (fraction < 1) motion = requestAnimationFrame(tick);
    };
    motion = requestAnimationFrame(tick);
  }
  new ResizeObserver(() => drawWires()).observe($('world'));
  new IntersectionObserver(entries => { storyVisible = entries[0].isIntersecting; mobileControls(); }, { threshold: 0 }).observe(document.querySelector('.story'));
  new IntersectionObserver(entries => { startVisible = entries[0].isIntersecting; mobileControls(); }, { threshold: 0 }).observe($('getting-started'));
  narrow.addEventListener('change', () => { mobileControls(); drawWires(); });
  reduceQuery.addEventListener('change', () => drawWires());
  window.addEventListener('pagehide', stop);
  window.addEventListener('pageshow', () => render());
  syncInputs();
  render();
})();
