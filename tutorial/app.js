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
  function choose(chapter, side = 'alice', text = '') {
    stop(); closeInspector(); clearExtras();
    state = M.create(chapter, side, text, state.offline);
    $('why').open = false;
    const preset = M.chapters.find(c => c.id === chapter).command;
    $('alice-command').value = preset;
    $('bob-command').value = chapter === 'connect' ? 'bootstrap' : chapter === 'human' ? 'say "I agree with this proposal."' : 'send "I checked the retry behavior."';
    render(true);
  }
  function showHistory(side) {
    const output = $(`${side}-output`);
    output.replaceChildren();
    const entries = [...M.history(state, side), ...extra[side]];
    if (!entries.length) {
      const blank = document.createElement('p'); blank.className = 'terminal-line empty';
      blank.textContent = `Waiting for ${M.names[side]}’s part of this example.`; output.append(blank);
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
    $('packet-label').textContent = current.sealed ? 'Illustrated encrypted content' : 'In this step';
    $('packet-content').textContent = current.packet || current.status;
    $('packet').classList.toggle('sealed', !!current.sealed);
    for (const side of ['alice', 'bob']) {
      const caption = $(side + '-crypto').querySelector('small');
      caption.textContent = state.chapter === 'connect' ? 'Sign / verify' : side === state.side ? 'Sign / encrypt' : 'Decrypt / verify';
    }
    $('repo-state').textContent = current.archived ? 'Example message saved' : state.chapter === 'connect' ? current.status : 'Public identities + sealed records';
    const offline = !!current.blockedBroker || (state.offline && state.chapter === 'message');
    $('jetstream').classList.toggle('offline', offline);
    $('broker-state').textContent = offline ? 'Paused in this example' : current.archived ? 'Notice after Git confirmation' : 'Wakes active listeners';
    $('broker-toggle').textContent = state.offline ? 'Resume broker in example' : 'Pause broker in example';
    $('broker-toggle').setAttribute('aria-pressed', String(state.offline));
    $('broker-toggle').disabled = state.chapter !== 'message';
    $('previous').disabled = state.index === 0;
    $('play').textContent = playing ? 'Pause' : last ? 'Replay flow' : 'Play flow';
    $('play').disabled = M.needsApproval(state);
    $('next').textContent = M.needsApproval(state) ? 'Review example' : last ? state.chapter === 'recovery' ? 'Start again' : 'Next chapter →' : 'Next step →';
    $('mobile-count').textContent = `${state.index + 1}/${frames.length}`;
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
  $('replay').addEventListener('click', () => { choose(state.chapter, state.side, state.text); });
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
    state = M.create('message', state.side, state.text, offline); clearExtras(); render(true);
  });

  for (const side of ['alice', 'bob']) {
    $(`${side}-form`).addEventListener('submit', event => {
      event.preventDefault(); stop(); closeInspector();
      const result = M.parse($(`${side}-command`).value, side);
      if (result.error) { $(`${side}-error`).textContent = result.error; render(); announce(result.error); return; }
      $(`${side}-error`).textContent = '';
      if (result.help) {
        extra[side].push({ kind: 'result', text: 'Demo shortcuts: bootstrap · send "text" · say "text" · inbox\nRun animates the explanation. No command is executed.' }); render(); return;
      }
      clearExtras(); state = { ...result.state, offline: state.offline }; $('why').open = false;
      playing = true; render(true); timer = setTimeout(step, 3100);
    });
  }
  document.querySelectorAll('[data-fill]').forEach(button => button.addEventListener('click', () => {
    const [side, command] = button.dataset.fill.split(':');
    const value = command === 'send' ? `send "${side === 'alice' ? 'Can you review the retry logic?' : 'I checked the retry behavior.'}"` : command === 'say' ? 'say "I approve this direction."' : command;
    $(`${side}-command`).value = value; $(`${side}-command`).focus();
  }));

  function closeInspector() {
    $('inspector').hidden = true;
    if (selected) selected.removeAttribute('data-selected');
    selected = null;
  }
  document.querySelectorAll('[data-object]').forEach(button => button.addEventListener('click', () => {
    stop(); render();
    const object = M.objects[button.dataset.object];
    if (selected) selected.removeAttribute('data-selected');
    selected = button; selected.setAttribute('data-selected', 'true');
    $('object-owner').textContent = button.dataset.side ? `${M.names[button.dataset.side]}’s side` : 'Shared infrastructure';
    $('object-title').textContent = object.title; $('object-job').textContent = object.job;
    $('object-detail').textContent = object.detail; $('object-why').textContent = object.why;
    $('inspector').hidden = false; $('inspector-close').focus({ preventScroll: true });
  }));
  $('inspector-close').addEventListener('click', () => { const back = selected; closeInspector(); back?.focus({ preventScroll: true }); });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !$('inspector').hidden) { const back = selected; closeInspector(); back?.focus({ preventScroll: true }); }
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
    $('approval-dialog').close(); extra[state.side] = []; state = M.approve(state); render(true); (approvalReturnTarget || $('next')).focus({ preventScroll: true });
  });
  function cancelApproval() {
    $('approval-dialog').close();
    extra[state.side].push({ kind: 'result', text: 'Example cancelled. No signature illustrated.' });
    render(); (approvalReturnTarget || $('next')).focus({ preventScroll: true });
  }
  $('approval-cancel').addEventListener('click', cancelApproval);
  $('approval-dialog').addEventListener('cancel', event => { event.preventDefault(); cancelApproval(); });

  function showStart(show) {
    stop(); render(); closeInspector();
    $('getting-started').hidden = !show;
    $('start-toggle').setAttribute('aria-expanded', String(show));
    if (show) { $('getting-started').scrollIntoView({ behavior: reduceQuery.matches ? 'instant' : 'smooth', block: 'start' }); }
    else { $('start-toggle').focus(); }
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
  function drawWires(animate = false) {
    cancelAnimationFrame(motion); $('traveller').style.opacity = '0';
    const box = $('world').getBoundingClientRect();
    $('wires').setAttribute('viewBox', `0 0 ${box.width} ${box.height}`);
    $('wire-paths').replaceChildren();
    const route = M.current(state).route, paths = [];
    const coords = id => {
      const r = $(id).getBoundingClientRect();
      return { x: r.left - box.left, y: r.top - box.top, w: r.width, h: r.height, cx: r.left - box.left + r.width / 2, cy: r.top - box.top + r.height / 2 };
    };
    for (let i = 0; i < route.length - 1; i++) {
      if (route[i] === route[i + 1]) continue;
      const a = coords(route[i]), b = coords(route[i + 1]);
      const dx = b.cx - a.cx, dy = b.cy - a.cy;
      let d;
      const biometricGesture = route[i].endsWith('-human') && route[i + 1].endsWith('-biometric');
      if (biometricGesture) {
        const right = route[i].startsWith('bob'), gutter = right ? box.width - 2 : 2;
        const ax = right ? a.x + a.w : a.x, bx = right ? b.x + b.w : b.x;
        d = `M ${ax} ${a.cy} C ${gutter} ${a.cy} ${gutter} ${b.cy} ${bx} ${b.cy}`;
      } else if (Math.abs(dx) > Math.abs(dy) * .7) {
        const ax = dx > 0 ? a.x + a.w : a.x, bx = dx > 0 ? b.x : b.x + b.w;
        const mid = (ax + bx) / 2;
        d = `M ${ax} ${a.cy} C ${mid} ${a.cy} ${mid} ${b.cy} ${bx} ${b.cy}`;
      } else {
        const ay = dy > 0 ? a.y + a.h : a.y, by = dy > 0 ? b.y : b.y + b.h;
        const mid = (ay + by) / 2;
        d = `M ${a.cx} ${ay} C ${a.cx} ${mid} ${b.cx} ${mid} ${b.cx} ${by}`;
      }
      const path = document.createElementNS(NS, 'path'); path.setAttribute('d', d);
      const type = [route[i], route[i + 1]].some(id => id.endsWith('-llm')) ? 'reasoning' : [route[i], route[i + 1]].includes('jetstream') ? 'notification' : '';
      path.setAttribute('class', `wire ${type}`); $('wire-paths').append(path); paths.push(path);
    }
    if (!animate || reduceQuery.matches || !paths.length) return;
    const lengths = paths.map(p => p.getTotalLength()), total = lengths.reduce((a, b) => a + b, 0), start = performance.now();
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
  const narrow = window.matchMedia('(max-width: 780px)');
  let storyVisible = true;
  function mobileControls() { $('mobile-playback').hidden = !narrow.matches || storyVisible; }
  new IntersectionObserver(entries => { storyVisible = entries[0].isIntersecting; mobileControls(); }, { threshold: 0 }).observe(document.querySelector('.story'));
  narrow.addEventListener('change', mobileControls);
  reduceQuery.addEventListener('change', () => drawWires());
  window.addEventListener('pagehide', stop);
  window.addEventListener('pageshow', () => render());
  render();
})();
