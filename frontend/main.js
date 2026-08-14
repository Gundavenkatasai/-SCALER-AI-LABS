const API = 'http://localhost:8000/api';

// ---- Tab navigation -----------------------------------------------------

const panels = {
  upload: document.getElementById('panel-upload'),
  history: document.getElementById('panel-history'),
};
const navBtns = {
  upload: document.getElementById('nav-upload'),
  history: document.getElementById('nav-history'),
};

function switchTab(name) {
  Object.entries(panels).forEach(([k, el]) => el.classList.toggle('active', k === name));
  Object.entries(navBtns).forEach(([k, btn]) => btn.classList.toggle('active', k === name));
  if (name === 'history') loadHistory();
}

navBtns.upload.addEventListener('click', () => switchTab('upload'));
navBtns.history.addEventListener('click', () => switchTab('history'));

// ---- Upload / Dropzone --------------------------------------------------

const uploadZone    = document.getElementById('upload-zone');
const dropContent   = document.getElementById('dropzone-content');
const fileInput     = document.getElementById('file-input');
const useNer        = document.getElementById('use-ner');
const processingEl  = document.getElementById('processing-overlay');
const resultsCard   = document.getElementById('results-section');

uploadZone.addEventListener('click', () => fileInput.click());

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evt =>
  uploadZone.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); })
);
['dragenter', 'dragover'].forEach(e => uploadZone.addEventListener(e, () => uploadZone.classList.add('over')));
['dragleave', 'drop'].forEach(e => uploadZone.addEventListener(e, () => uploadZone.classList.remove('over')));
uploadZone.addEventListener('drop', e => {
  if (e.dataTransfer.files[0]) submitFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', e => {
  if (e.target.files[0]) submitFile(e.target.files[0]);
});

async function submitFile(file) {
  if (!file.name.toLowerCase().endsWith('.docx')) {
    alert('Only .docx files are accepted.');
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    alert('File is too large (max 50 MB).');
    return;
  }

  // transition to processing state
  dropContent.style.opacity = '0';
  processingEl.style.display = 'flex';
  resultsCard.style.display  = 'none';

  const body = new FormData();
  body.append('file', file);
  body.append('use_ner', useNer.checked);

  try {
    const res  = await fetch(`${API}/redact`, { method: 'POST', body });
    const data = await res.json();

    if (!res.ok) throw new Error(data.detail || res.statusText);
    if (data.status !== 'success') throw new Error(data.detail || 'Unknown error');

    showResults(data, file.name);
  } catch (err) {
    alert(`Redaction failed: ${err.message}`);
    processingEl.style.display = 'none';
    dropContent.style.opacity  = '1';
  }
}

function showResults(data, originalName) {
  processingEl.style.display = 'none';
  dropContent.style.opacity  = '1';

  const s = data.summary;
  document.getElementById('stat-paragraphs').textContent = s.paragraphs_scanned.toLocaleString();
  document.getElementById('stat-entities').textContent   = s.unique_entities_redacted.toLocaleString();
  document.getElementById('stat-time').textContent       = s.processing_time_s ?? '—';
  document.getElementById('stat-ner').textContent        = s.spacy_used ? 'On' : 'Off';

  const tagsEl = document.getElementById('breakdown-tags');
  tagsEl.innerHTML = '';
  Object.entries(s.category_breakdown)
    .sort((a, b) => b[1] - a[1])
    .forEach(([cat, n]) => {
      const t = document.createElement('span');
      t.className = 'tag';
      t.innerHTML = `${cat.replace(/_/g, ' ')} <span class="tag-n">${n}</span>`;
      tagsEl.appendChild(t);
    });

  document.getElementById('download-doc').onclick = () => {
    window.location.href = `${API}/download/${data.download_id}`;
  };

  document.getElementById('download-json').onclick = () => {
    const blob = new Blob([JSON.stringify(data.mapping, null, 2)], { type: 'application/json' });
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `mapping_${originalName.replace('.docx', '')}.json`,
    });
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  resultsCard.style.display = 'block';
}

// ---- History ------------------------------------------------------------

async function loadHistory() {
  const listEl  = document.getElementById('history-list');
  const emptyEl = document.getElementById('history-empty');

  listEl.innerHTML = '';
  emptyEl.style.display = 'none';

  try {
    const res  = await fetch(`${API}/history`);
    const data = await res.json();
    const jobs = data.history || [];

    if (jobs.length === 0) {
      emptyEl.style.display = 'block';
      return;
    }

    jobs.forEach(job => listEl.appendChild(buildHistoryRow(job)));
  } catch {
    emptyEl.textContent = 'Could not load history. Is the server running?';
    emptyEl.style.display = 'block';
  }
}

function buildHistoryRow(job) {
  const li = document.createElement('li');
  li.className = 'history-item';
  li.dataset.jobId = job.id;

  const ts = new Date(job.timestamp).toLocaleString();
  const n  = job.summary?.unique_entities_redacted ?? '?';

  li.innerHTML = `
    <div class="history-info">
      <div class="history-filename" title="${job.filename}">${job.filename}</div>
      <div class="history-meta">${ts} &nbsp;·&nbsp; ${n} entities redacted</div>
    </div>
    <div class="history-actions">
      <button class="btn-icon" title="Download redacted file" data-action="download">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      </button>
      <button class="btn-icon danger" title="Delete this entry" data-action="delete">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
      </button>
    </div>
  `;

  li.querySelector('[data-action="download"]').addEventListener('click', () => {
    if (job.download_id) {
      window.location.href = `${API}/download/${job.download_id}`;
    } else {
      alert('No file available for this job.');
    }
  });

  li.querySelector('[data-action="delete"]').addEventListener('click', async () => {
    if (!confirm(`Delete the history entry for "${job.filename}"?`)) return;
    await fetch(`${API}/history/${job.id}`, { method: 'DELETE' });
    li.remove();
    const listEl = document.getElementById('history-list');
    if (!listEl.children.length) {
      document.getElementById('history-empty').style.display = 'block';
    }
  });

  return li;
}
