// ── State
let activeTab = 'dashboard';
let allMedications = [];
let allAppointments = [];
let allNotes = [];
let medsFilter = 'active';
let apptsFilter = 'upcoming';

// ── Tab switching
function switchTab(tab) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item,.bnav-item').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  const panel = document.getElementById('tab-' + tab);
  if (panel) panel.classList.add('active');
  activeTab = tab;
  const titles = { dashboard:'Dashboard', chat:'AI Advisor', vitals:'Vitals',
    medications:'Medications', symptoms:'Symptoms', appointments:'Appointments',
    notes:'Notes', profile:'Profile' };
  const mt = document.getElementById('mobileTitle');
  if (mt) mt.textContent = titles[tab] || tab;
  const mm = document.getElementById('moreMenu');
  if (mm) mm.style.display = 'none';
  switch (tab) {
    case 'dashboard': loadDashboard(); break;
    case 'chat': loadChatHistory(); break;
    case 'vitals': loadVitals(); break;
    case 'medications': loadMedications(); break;
    case 'symptoms': loadSymptoms(); break;
    case 'appointments': loadAppointments(); break;
    case 'notes': loadNotes(); break;
    case 'profile': loadProfile(); break;
  }
}

// ── API
async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

// ── Toast
function showToast(msg, dur) {
  dur = dur || 2500;
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), dur);
}

// ── Helpers
function toggleForm(id) {
  const el = document.getElementById(id);
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function nowLocal() {
  const d = new Date();
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 16);
}

function fmtDate(s) {
  if (!s) return '—';
  const d = new Date(s);
  if (isNaN(d)) return String(s).slice(0,10);
  return d.toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' });
}

function fmtDatetime(s) {
  if (!s) return '—';
  const d = new Date(s);
  if (isNaN(d)) return String(s);
  return d.toLocaleString(undefined, { month:'short', day:'numeric', hour:'numeric', minute:'2-digit' });
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Dashboard
async function loadDashboard() {
  try {
    const d = await api('/api/dashboard');
    document.getElementById('stat-vitals').textContent = d.stats.vitals;
    document.getElementById('stat-meds').textContent = d.stats.medications;
    document.getElementById('stat-symptoms').textContent = d.stats.symptoms_30d;
    document.getElementById('stat-appts').textContent = d.stats.upcoming_appts;
    const name = d.profile && d.profile.name;
    const h = new Date().getHours();
    const greet = h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening';
    document.getElementById('dash-greeting').textContent = name ? greet + ', ' + name + '!' : greet + '!';
    // Latest vitals
    const vg = document.getElementById('latestVitalsGrid');
    const vl = { blood_pressure_systolic:'BP Systolic', blood_pressure_diastolic:'BP Diastolic',
      heart_rate:'Heart Rate', weight:'Weight', blood_glucose:'Blood Glucose',
      oxygen_saturation:'O₂ Sat', temperature:'Temp', bmi:'BMI' };
    const lv = d.latest_vitals;
    if (Object.keys(lv).length > 0) {
      vg.innerHTML = Object.entries(lv).map(([k,v]) =>
        '<div class="vital-chip"><div class="vital-chip-label">' + (vl[k]||k) +
        '</div><div class="vital-chip-value">' + v.value + (v.unit ? ' '+v.unit : '') +
        '</div><div class="vital-chip-date">' + fmtDate(v.recorded_at) + '</div></div>'
      ).join('');
    } else {
      vg.innerHTML = '<p class="empty-state">No vitals yet</p>';
    }
    // Upcoming appointments
    const ua = document.getElementById('upcomingAppts');
    if (d.upcoming_appointments.length > 0) {
      ua.innerHTML = d.upcoming_appointments.map(a =>
        '<div class="appt-item"><div class="appt-date-badge">' + fmtDate(a.date) +
        '</div><div class="appt-info"><h4>' + esc(a.title) + '</h4><p>' +
        (a.doctor ? esc(a.doctor) : '') + (a.time ? ' · '+a.time : '') + '</p></div></div>'
      ).join('');
    } else {
      ua.innerHTML = '<p class="empty-state">No upcoming appointments</p>';
    }
    // Recent symptoms
    const rs = document.getElementById('recentSymptoms');
    if (d.recent_symptoms.length > 0) {
      rs.innerHTML = d.recent_symptoms.map(s => {
        const sev = s.severity || 0;
        const dot = sev >= 7 ? 'sev-high' : sev >= 4 ? 'sev-med' : 'sev-low';
        return '<span class="symptom-tag"><span class="severity-dot '+dot+'"></span>' + esc(s.description) + '</span>';
      }).join('');
    } else {
      rs.innerHTML = '<p class="empty-state">No recent symptoms</p>';
    }
  } catch(e) { console.error('Dashboard:', e); }
}

// ── Chat
async function loadChatHistory() {
  try {
    const history = await api('/api/chat/history');
    if (history.length > 1) {
      document.getElementById('chatMessages').innerHTML = history.map(m => renderMsg(m.role, m.content)).join('');
      scrollChat();
    }
  } catch(e) {}
}

function renderMsg(role, content) {
  const avatar = role === 'user' ? '&#x1F464;' : '&#x1F916;';
  const safe = esc(content).replace(/\n\n/g,'</p><p>').replace(/\n/g,'<br>');
  return '<div class="chat-message '+role+'">' +
    '<div class="message-avatar">'+avatar+'</div>' +
    '<div class="message-bubble"><p>'+safe+'</p></div></div>';
}

function scrollChat() {
  const el = document.getElementById('chatMessages');
  el.scrollTop = el.scrollHeight;
}

async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  input.style.height = 'auto';
  const msgs = document.getElementById('chatMessages');
  msgs.insertAdjacentHTML('beforeend', renderMsg('user', msg));
  const tid = 'typing_' + Date.now();
  msgs.insertAdjacentHTML('beforeend',
    '<div class="chat-message assistant" id="'+tid+'">' +
    '<div class="message-avatar">&#x1F916;</div>' +
    '<div class="message-bubble"><div class="typing-indicator">' +
    '<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>' +
    '</div></div></div>'
  );
  scrollChat();
  document.getElementById('chatSend').disabled = true;
  try {
    const data = await api('/api/chat', { method:'POST', body:{ message:msg } });
    const te = document.getElementById(tid);
    if (te) te.remove();
    msgs.insertAdjacentHTML('beforeend', renderMsg('assistant', data.response));
    scrollChat();
  } catch(e) {
    const te = document.getElementById(tid);
    if (te) te.remove();
    msgs.insertAdjacentHTML('beforeend', renderMsg('assistant', '⚠️ Error reaching server. Please try again.'));
    scrollChat();
  } finally {
    document.getElementById('chatSend').disabled = false;
    input.focus();
  }
}

function askQuick(prompt) {
  document.getElementById('chatInput').value = prompt;
  sendChat();
}

// ── Vitals
const VITAL_UNITS = {
  blood_pressure_systolic:'mmHg', blood_pressure_diastolic:'mmHg',
  heart_rate:'bpm', weight:'kg', blood_glucose:'mg/dL',
  oxygen_saturation:'%', temperature:'°F', bmi:'',
  cholesterol_total:'mg/dL', cholesterol_ldl:'mg/dL',
  cholesterol_hdl:'mg/dL', triglycerides:'mg/dL', hba1c:'%'
};

async function loadVitals() {
  const filter = document.getElementById('vitalFilter').value;
  try {
    const url = filter ? '/api/vitals?type='+encodeURIComponent(filter) : '/api/vitals';
    const vitals = await api(url);
    const list = document.getElementById('vitalsList');
    if (!vitals.length) { list.innerHTML = '<p class="empty-state">No vitals logged yet.</p>'; return; }
    list.innerHTML = vitals.map(v => {
      const label = v.type.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      return '<div class="data-item">' +
        '<div class="data-item-body">' +
        '<div class="data-item-title">' + esc(label) + '</div>' +
        '<div class="data-item-meta"><strong>' + v.value + (v.unit?' '+v.unit:'') + '</strong> · ' +
        fmtDatetime(v.recorded_at) + (v.notes ? ' · '+esc(v.notes) : '') + '</div></div>' +
        '<div class="data-item-actions"><button class="btn-danger" onclick="deleteVital('+v.id+')">&#x2715;</button></div></div>';
    }).join('');
  } catch(e) { document.getElementById('vitalsList').innerHTML = '<p class="empty-state">Error loading.</p>'; }
}

async function saveVital() {
  const type = document.getElementById('vitalType').value;
  const value = parseFloat(document.getElementById('vitalValue').value);
  if (!type || isNaN(value)) { showToast('Please enter type and value'); return; }
  const unit = document.getElementById('vitalUnit').value || (VITAL_UNITS[type] || '');
  const notes = document.getElementById('vitalNotes').value;
  const ds = document.getElementById('vitalDate').value;
  try {
    await api('/api/vitals', { method:'POST', body:{ type, value, unit, notes,
      recorded_at: ds ? new Date(ds).toISOString() : undefined } });
    showToast('✅ Vital logged');
    document.getElementById('vitalForm').style.display = 'none';
    document.getElementById('vitalValue').value = '';
    document.getElementById('vitalNotes').value = '';
    loadVitals();
  } catch(e) { showToast('❌ Error saving'); }
}

async function deleteVital(id) {
  if (!confirm('Delete this entry?')) return;
  try { await api('/api/vitals/'+id, { method:'DELETE' }); showToast('Deleted'); loadVitals(); }
  catch(e) { showToast('❌ Error'); }
}

// ── Medications
async function loadMedications() {
  try { allMedications = await api('/api/medications'); renderMedications(); }
  catch(e) {}
}

function filterMeds(f, btn) {
  medsFilter = f;
  document.querySelectorAll('#tab-medications .section-tab').forEach(b => b.classList.toggle('active', b===btn));
  renderMedications();
}

function renderMedications() {
  const list = document.getElementById('medsList');
  let meds = medsFilter === 'active' ? allMedications.filter(m=>m.active===1) : allMedications;
  if (!meds.length) { list.innerHTML = '<p class="empty-state">No medications found.</p>'; return; }
  list.innerHTML = meds.map(m =>
    '<div class="data-item"><div class="data-item-body">' +
    '<div class="data-item-title">' + esc(m.name) +
    '<span class="badge '+(m.active?'badge-active':'badge-inactive')+'">'+(m.active?'Active':'Inactive')+'</span></div>' +
    '<div class="data-item-meta">' +
    (m.dosage ? esc(m.dosage) : '') +
    (m.frequency ? ' · '+esc(m.frequency) : '') +
    (m.start_date ? ' · Started '+fmtDate(m.start_date) : '') +
    (m.notes ? '<br>'+esc(m.notes) : '') +
    '</div></div>' +
    '<div class="data-item-actions">' +
    '<button class="btn-sm" onclick="editMed('+m.id+')">Edit</button>' +
    '<button class="btn-danger" onclick="deleteMed('+m.id+')">&#x2715;</button>' +
    '</div></div>'
  ).join('');
}

function editMed(id) {
  const m = allMedications.find(x=>x.id===id);
  if (!m) return;
  document.getElementById('medFormTitle').textContent = 'Edit Medication';
  document.getElementById('medEditId').value = id;
  document.getElementById('medName').value = m.name||'';
  document.getElementById('medDosage').value = m.dosage||'';
  document.getElementById('medFrequency').value = m.frequency||'';
  document.getElementById('medStart').value = m.start_date||'';
  document.getElementById('medEnd').value = m.end_date||'';
  document.getElementById('medActive').value = m.active!==undefined ? m.active : 1;
  document.getElementById('medNotes').value = m.notes||'';
  document.getElementById('medForm').style.display = 'block';
  document.getElementById('medForm').scrollIntoView({behavior:'smooth'});
}

function cancelMedForm() {
  document.getElementById('medForm').style.display = 'none';
  document.getElementById('medEditId').value = '';
  document.getElementById('medFormTitle').textContent = 'Add Medication';
  ['medName','medDosage','medFrequency','medStart','medEnd','medNotes'].forEach(id => {
    document.getElementById(id).value = '';
  });
  document.getElementById('medActive').value = '1';
}

async function saveMedication() {
  const name = document.getElementById('medName').value.trim();
  if (!name) { showToast('Medication name is required'); return; }
  const editId = document.getElementById('medEditId').value;
  const data = { name,
    dosage: document.getElementById('medDosage').value,
    frequency: document.getElementById('medFrequency').value,
    start_date: document.getElementById('medStart').value,
    end_date: document.getElementById('medEnd').value,
    notes: document.getElementById('medNotes').value,
    active: parseInt(document.getElementById('medActive').value)
  };
  try {
    if (editId) await api('/api/medications/'+editId, { method:'PUT', body:data });
    else await api('/api/medications', { method:'POST', body:data });
    showToast('✅ Medication saved');
    cancelMedForm();
    loadMedications();
  } catch(e) { showToast('❌ Error saving'); }
}

async function deleteMed(id) {
  if (!confirm('Delete this medication?')) return;
  try { await api('/api/medications/'+id, { method:'DELETE' }); showToast('Deleted'); loadMedications(); }
  catch(e) { showToast('❌ Error'); }
}

// ── Symptoms
async function loadSymptoms() {
  try {
    const symptoms = await api('/api/symptoms');
    const list = document.getElementById('symptomsList');
    if (!symptoms.length) { list.innerHTML = '<p class="empty-state">No symptoms logged yet.</p>'; return; }
    list.innerHTML = symptoms.map(s => {
      const sev = s.severity || 0;
      const sevColor = sev >= 7 ? '#ef4444' : sev >= 4 ? '#f59e0b' : '#10b981';
      return '<div class="data-item"><div class="data-item-body">' +
        '<div class="data-item-title">' + esc(s.description) + '</div>' +
        '<div class="data-item-meta">' +
        (s.severity ? '<span style="color:'+sevColor+';font-weight:600">Severity '+s.severity+'/10</span> · ' : '') +
        (s.body_area ? esc(s.body_area)+' · ' : '') +
        fmtDatetime(s.recorded_at) +
        (s.notes ? '<br>'+esc(s.notes) : '') +
        '</div></div>' +
        '<div class="data-item-actions"><button class="btn-danger" onclick="deleteSymptom('+s.id+')">&#x2715;</button></div></div>';
    }).join('');
  } catch(e) {}
}

async function saveSymptom() {
  const desc = document.getElementById('symptomDesc').value.trim();
  if (!desc) { showToast('Please describe the symptom'); return; }
  const ds = document.getElementById('symptomDate').value;
  try {
    await api('/api/symptoms', { method:'POST', body:{
      description: desc,
      severity: parseInt(document.getElementById('symptomSeverity').value),
      body_area: document.getElementById('symptomArea').value,
      notes: document.getElementById('symptomNotes').value,
      recorded_at: ds ? new Date(ds).toISOString() : undefined
    }});
    showToast('✅ Symptom logged');
    document.getElementById('symptomForm').style.display = 'none';
    document.getElementById('symptomDesc').value = '';
    document.getElementById('symptomArea').value = '';
    document.getElementById('symptomNotes').value = '';
    document.getElementById('symptomSeverity').value = 5;
    document.getElementById('severityValue').textContent = '5';
    loadSymptoms();
  } catch(e) { showToast('❌ Error saving'); }
}

async function deleteSymptom(id) {
  if (!confirm('Delete this entry?')) return;
  try { await api('/api/symptoms/'+id, { method:'DELETE' }); showToast('Deleted'); loadSymptoms(); }
  catch(e) { showToast('❌ Error'); }
}

// ── Appointments
async function loadAppointments() {
  try { allAppointments = await api('/api/appointments'); renderAppointments(); }
  catch(e) {}
}

function filterAppts(f, btn) {
  apptsFilter = f;
  document.querySelectorAll('#tab-appointments .section-tab').forEach(b => b.classList.toggle('active', b===btn));
  renderAppointments();
}

function renderAppointments() {
  const list = document.getElementById('apptsList');
  const today = new Date().toISOString().slice(0,10);
  let appts = allAppointments;
  if (apptsFilter === 'upcoming') appts = appts.filter(a => !a.completed && a.date >= today);
  else if (apptsFilter === 'completed') appts = appts.filter(a => a.completed);
  if (!appts.length) { list.innerHTML = '<p class="empty-state">No appointments found.</p>'; return; }
  list.innerHTML = appts.map(a =>
    '<div class="data-item'+(a.completed?' completed-item':'')+'">' +
    '<div class="data-item-body">' +
    '<div class="data-item-title">' + esc(a.title) +
    (a.completed ? '<span class="badge completed-badge">✓ Done</span>' : '') + '</div>' +
    '<div class="data-item-meta">' +
    (a.doctor ? esc(a.doctor)+' · ' : '') +
    (a.date ? fmtDate(a.date) : '') +
    (a.time ? ' at '+a.time : '') +
    (a.location ? ' · '+esc(a.location) : '') +
    (a.notes ? '<br>'+esc(a.notes) : '') +
    '</div></div>' +
    '<div class="data-item-actions">' +
    (!a.completed ? '<button class="btn-sm" onclick="markApptDone('+a.id+')">&#x2713;</button>' : '') +
    '<button class="btn-sm" onclick="editAppt('+a.id+')">Edit</button>' +
    '<button class="btn-danger" onclick="deleteAppt('+a.id+')">&#x2715;</button>' +
    '</div></div>'
  ).join('');
}

async function markApptDone(id) {
  const a = allAppointments.find(x=>x.id===id);
  if (!a) return;
  try {
    await api('/api/appointments/'+id, { method:'PUT', body:{...a, completed:1} });
    showToast('✅ Marked complete');
    loadAppointments();
  } catch(e) { showToast('❌ Error'); }
}

function editAppt(id) {
  const a = allAppointments.find(x=>x.id===id);
  if (!a) return;
  document.getElementById('apptFormTitle').textContent = 'Edit Appointment';
  document.getElementById('apptEditId').value = id;
  document.getElementById('apptTitle').value = a.title||'';
  document.getElementById('apptDoctor').value = a.doctor||'';
  document.getElementById('apptLocation').value = a.location||'';
  document.getElementById('apptDate').value = a.date||'';
  document.getElementById('apptTime').value = a.time||'';
  document.getElementById('apptNotes').value = a.notes||'';
  document.getElementById('apptForm').style.display = 'block';
  document.getElementById('apptForm').scrollIntoView({behavior:'smooth'});
}

function cancelApptForm() {
  document.getElementById('apptForm').style.display = 'none';
  document.getElementById('apptEditId').value = '';
  document.getElementById('apptFormTitle').textContent = 'Add Appointment';
  ['apptTitle','apptDoctor','apptLocation','apptDate','apptTime','apptNotes'].forEach(id => {
    document.getElementById(id).value = '';
  });
}

async function saveAppointment() {
  const title = document.getElementById('apptTitle').value.trim();
  if (!title) { showToast('Title is required'); return; }
  const editId = document.getElementById('apptEditId').value;
  const data = { title,
    doctor: document.getElementById('apptDoctor').value,
    location: document.getElementById('apptLocation').value,
    date: document.getElementById('apptDate').value,
    time: document.getElementById('apptTime').value,
    notes: document.getElementById('apptNotes').value,
    completed: editId ? (allAppointments.find(a=>a.id===parseInt(editId))?.completed||0) : 0
  };
  try {
    if (editId) await api('/api/appointments/'+editId, { method:'PUT', body:data });
    else await api('/api/appointments', { method:'POST', body:data });
    showToast('✅ Appointment saved');
    cancelApptForm();
    loadAppointments();
  } catch(e) { showToast('❌ Error saving'); }
}

async function deleteAppt(id) {
  if (!confirm('Delete this appointment?')) return;
  try { await api('/api/appointments/'+id, { method:'DELETE' }); showToast('Deleted'); loadAppointments(); }
  catch(e) { showToast('❌ Error'); }
}

// ── Notes
async function loadNotes() {
  try { allNotes = await api('/api/notes'); renderNotes(); }
  catch(e) {}
}

function renderNotes() {
  const grid = document.getElementById('notesList');
  if (!allNotes.length) { grid.innerHTML = '<p class="empty-state">No notes yet.</p>'; return; }
  grid.innerHTML = allNotes.map(n =>
    '<div class="note-card">' +
    '<div class="note-card-header">' +
    '<span class="note-card-title">'+(n.title ? esc(n.title) : 'Note')+'</span>' +
    '<div><button class="btn-sm" onclick="editNote('+n.id+')">Edit</button> ' +
    '<button class="btn-danger" onclick="deleteNote('+n.id+')">&#x2715;</button></div></div>' +
    '<div class="note-card-content">'+esc(n.content).substring(0,250)+(n.content.length>250?'…':'')+'</div>' +
    '<div class="note-card-footer">' +
    '<div class="note-tags">'+(n.tags||'').split(',').filter(Boolean).map(t=>'<span class="note-tag">'+esc(t.trim())+'</span>').join('')+'</div>' +
    '<span class="note-date">'+fmtDate(n.updated_at)+'</span>' +
    '</div></div>'
  ).join('');
}

function editNote(id) {
  const n = allNotes.find(x=>x.id===id);
  if (!n) return;
  document.getElementById('noteFormTitle').textContent = 'Edit Note';
  document.getElementById('noteEditId').value = id;
  document.getElementById('noteTitle').value = n.title||'';
  document.getElementById('noteContent').value = n.content||'';
  document.getElementById('noteTags').value = n.tags||'';
  document.getElementById('noteForm').style.display = 'block';
  document.getElementById('noteForm').scrollIntoView({behavior:'smooth'});
}

function cancelNoteForm() {
  document.getElementById('noteForm').style.display = 'none';
  document.getElementById('noteEditId').value = '';
  document.getElementById('noteFormTitle').textContent = 'New Note';
  ['noteTitle','noteContent','noteTags'].forEach(id => { document.getElementById(id).value = ''; });
}

async function saveNote() {
  const content = document.getElementById('noteContent').value.trim();
  if (!content) { showToast('Note content is required'); return; }
  const editId = document.getElementById('noteEditId').value;
  const data = { title: document.getElementById('noteTitle').value, content,
    tags: document.getElementById('noteTags').value };
  try {
    if (editId) await api('/api/notes/'+editId, { method:'PUT', body:data });
    else await api('/api/notes', { method:'POST', body:data });
    showToast('✅ Note saved');
    cancelNoteForm();
    loadNotes();
  } catch(e) { showToast('❌ Error saving'); }
}

async function deleteNote(id) {
  if (!confirm('Delete this note?')) return;
  try { await api('/api/notes/'+id, { method:'DELETE' }); showToast('Deleted'); loadNotes(); }
  catch(e) { showToast('❌ Error'); }
}

// ── Profile
async function loadProfile() {
  try {
    const p = await api('/api/profile');
    if (Object.keys(p).length) {
      document.getElementById('profName').value = p.name||'';
      document.getElementById('profAge').value = p.age||'';
      document.getElementById('profGender').value = p.gender||'';
      document.getElementById('profBloodType').value = p.blood_type||'';
      document.getElementById('profHeight').value = p.height_cm||'';
      document.getElementById('profWeight').value = p.weight_kg||'';
      document.getElementById('profConditions').value = p.conditions||'';
      document.getElementById('profAllergies').value = p.allergies||'';
      document.getElementById('profEmergency').value = p.emergency_contact||'';
    }
  } catch(e) {}
}

async function saveProfile() {
  const data = {
    name: document.getElementById('profName').value,
    age: parseInt(document.getElementById('profAge').value)||null,
    gender: document.getElementById('profGender').value,
    blood_type: document.getElementById('profBloodType').value,
    height_cm: parseFloat(document.getElementById('profHeight').value)||null,
    weight_kg: parseFloat(document.getElementById('profWeight').value)||null,
    conditions: document.getElementById('profConditions').value,
    allergies: document.getElementById('profAllergies').value,
    emergency_contact: document.getElementById('profEmergency').value
  };
  try {
    await api('/api/profile', { method:'POST', body:data });
    const st = document.getElementById('profileSaveStatus');
    st.textContent = '✅ Profile saved successfully';
    setTimeout(()=>{ st.textContent=''; }, 3000);
    showToast('✅ Profile saved');
  } catch(e) { showToast('❌ Error saving profile'); }
}

// ── Report
function downloadReport() {
  showToast('Ὄ4 Generating report...');
  window.location.href = '/api/report';
}

// ── Init
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('vitalDate').value = nowLocal();
  document.getElementById('symptomDate').value = nowLocal();

  // Sidebar nav
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Bottom nav
  document.querySelectorAll('.bnav-item').forEach(btn => {
    if (btn.id === 'moreBtn') {
      btn.addEventListener('click', () => {
        const mm = document.getElementById('moreMenu');
        mm.style.display = mm.style.display === 'none' ? 'block' : 'none';
      });
    } else {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    }
  });

  document.querySelectorAll('.more-item').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('moreMenu').style.display = 'none';
      if (btn.dataset.tab) switchTab(btn.dataset.tab);
    });
  });

  document.getElementById('addVitalBtn').addEventListener('click', () => {
    document.getElementById('vitalDate').value = nowLocal();
    const type = document.getElementById('vitalType').value;
    document.getElementById('vitalUnit').value = VITAL_UNITS[type] || '';
    document.getElementById('vitalForm').style.display = 'block';
  });

  document.getElementById('vitalType').addEventListener('change', function() {
    document.getElementById('vitalUnit').value = VITAL_UNITS[this.value] || '';
  });

  document.getElementById('addMedBtn').addEventListener('click', () => {
    cancelMedForm();
    document.getElementById('medForm').style.display = 'block';
  });

  document.getElementById('addSymptomBtn').addEventListener('click', () => {
    document.getElementById('symptomDate').value = nowLocal();
    document.getElementById('symptomForm').style.display = 'block';
  });

  document.getElementById('addApptBtn').addEventListener('click', () => {
    cancelApptForm();
    document.getElementById('apptForm').style.display = 'block';
  });

  document.getElementById('addNoteBtn').addEventListener('click', () => {
    cancelNoteForm();
    document.getElementById('noteForm').style.display = 'block';
  });

  document.getElementById('reportBtn').addEventListener('click', downloadReport);
  document.getElementById('mobileReportBtn').addEventListener('click', downloadReport);

  // Chat
  document.getElementById('chatSend').addEventListener('click', sendChat);
  document.getElementById('chatInput').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
  });
  document.getElementById('chatInput').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 120) + 'px';
  });

  document.getElementById('clearChatBtn').addEventListener('click', async () => {
    if (!confirm('Clear all chat history?')) return;
    await api('/api/chat/clear', { method:'POST' });
    document.getElementById('chatMessages').innerHTML =
      '<div class="chat-message assistant">' +
      '<div class="message-avatar">&#x1F916;</div>' +
      '<div class="message-bubble"><p>Chat cleared. How can I help you today?</p></div></div>';
    showToast('Chat cleared');
  });

  document.addEventListener('click', e => {
    const mm = document.getElementById('moreMenu');
    const mb = document.getElementById('moreBtn');
    if (mm && mb && !mm.contains(e.target) && !mb.contains(e.target)) {
      mm.style.display = 'none';
    }
  });

  loadDashboard();
});
