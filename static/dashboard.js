// Variables globales
let currentTab = 'info';
let userInfo = null;
let documents = [];

// Inicialización
document.addEventListener('DOMContentLoaded', () => {
    loadUserInfo();
});

// ============= UTILIDADES =============

function showTab(tabName) {
    // Ocultar todos los tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remover clase active de todos los botones
    document.querySelectorAll('.tab').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Mostrar tab seleccionado
    document.getElementById(`tab-${tabName}`).classList.add('active');
    event.target.classList.add('active');
    
    currentTab = tabName;
    
    // Cargar datos según el tab
    if (tabName === 'documents' || tabName === 'encrypt' || tabName === 'sign') {
        refreshDocuments();
    }
    if (tabName === 'keys') {
        loadTeamKeys();
    }
}

function showAlert(message, type = 'info') {
    const alert = document.getElementById('globalAlert');
    alert.textContent = message;
    alert.className = `alert alert-${type}`;
    alert.style.display = 'block';
    
    setTimeout(() => {
        alert.style.display = 'none';
    }, 5000);
}

async function fetchAPI(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        if (response.status === 401) {
            window.location.href = '/';
            return null;
        }
        
        return await response.json();
    } catch (error) {
        showAlert('❌ Error de conexión: ' + error.message, 'error');
        return null;
    }
}

// ============= AUTENTICACIÓN =============

async function logout() {
    const data = await fetchAPI('/logout', { method: 'POST' });
    if (data) {
        window.location.href = '/';
    }
}

async function switchTeam() {
    const teamSelector = document.getElementById('teamSelector');
    const newTeam = teamSelector.value;
    
    const data = await fetchAPI('/switch_team', {
        method: 'POST',
        body: JSON.stringify({ team: newTeam })
    });
    
    if (data && data.success) {
        showAlert('✅ Equipo cambiado a: ' + newTeam, 'success');
        loadUserInfo();
    }
}

// ============= INFORMACIÓN DE USUARIO =============

async function loadUserInfo() {
    const data = await fetchAPI('/api/user_info');
    
    if (data) {
        userInfo = data;
        
        // Actualizar header
        document.getElementById('userName').textContent = data.username;
        document.getElementById('userRole').textContent = getRoleLabel(data.role);
        
        // Selector de equipo si tiene múltiples
        if (data.teams && data.teams.length > 1) {
            const teamSelector = document.getElementById('teamSelector');
            teamSelector.style.display = 'block';
            teamSelector.innerHTML = data.teams.map(team => 
                `<option value="${team}" ${team === data.team ? 'selected' : ''}>${team}</option>`
            ).join('');
            teamSelector.onchange = switchTeam;
        }
        
        // Actualizar tab de información
        document.getElementById('infoUsername').textContent = data.username;
        document.getElementById('infoTeam').textContent = data.team;
        document.getElementById('infoRole').textContent = getRoleLabel(data.role);
        document.getElementById('infoKeyStatus').textContent = data.has_keys ? '✅ Generadas' : '❌ No generadas';
        
        // Miembros del equipo
        const membersList = document.getElementById('teamMembersList');
        membersList.innerHTML = data.team_members.map(member => 
            `<li style="padding: 8px 0;">👤 ${member} ${member === data.username ? '(Tú)' : ''}</li>`
        ).join('');
        
        // Ocultar card de upload si no es abogado
        if (data.role !== 'abogado') {
            const uploadCard = document.getElementById('uploadCard');
            if (uploadCard) uploadCard.style.display = 'none';
            
            const encryptCard = document.getElementById('encryptCard');
            if (encryptCard) encryptCard.style.display = 'none';
            
            const encryptDocCard = document.getElementById('encryptDocCard');
            if (encryptDocCard) encryptDocCard.style.display = 'none';
            
            const wrapKeyCard = document.getElementById('wrapKeyCard');
            if (wrapKeyCard) wrapKeyCard.style.display = 'none';
        }
    }
}

function getRoleLabel(role) {
    const labels = {
        'abogado': '⚖️ Abogado',
        'cliente': '👤 Cliente',
        'otro': '📋 Notario/Organismo'
    };
    return labels[role] || role;
}

// ============= GESTIÓN DE LLAVES =============

async function generateKeys() {
    if (!confirm('¿Generar nuevo par de llaves RSA? Si ya tienes llaves, se sobrescribirán.')) {
        return;
    }
    
    showAlert('🔄 Generando llaves...', 'info');
    
    const data = await fetchAPI('/api/keys/generate', { method: 'POST' });
    
    if (data && data.success) {
        showAlert('✅ Llaves generadas exitosamente. Descarga tu llave privada ahora.', 'success');
        loadUserInfo();
        loadTeamKeys();
    } else {
        showAlert('❌ Error al generar llaves', 'error');
    }
}

async function downloadPrivateKey() {
    window.location.href = '/api/keys/download_private';
}

async function loadTeamKeys() {
    const data = await fetchAPI('/api/keys/team_members');
    
    if (data && data.success) {
        const keysList = document.getElementById('teamKeysList');
        if (data.members.length > 0) {
            keysList.innerHTML = data.members.map(member => 
                `<li style="padding: 8px 0;">🔑 ${member}</li>`
            ).join('');
        } else {
            keysList.innerHTML = '<li>No hay llaves públicas registradas</li>';
        }
    }
}

// ============= GESTIÓN DE DOCUMENTOS =============

async function uploadDocument() {
    const fileInput = document.getElementById('fileUpload');
    const file = fileInput.files[0];
    
    if (!file) {
        showAlert('⚠️ Selecciona un archivo', 'error');
        return;
    }
    
    if (!file.name.toLowerCase().endsWith('.pdf')) {
        showAlert('⚠️ Solo se permiten archivos PDF', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    showAlert('📤 Subiendo documento...', 'info');
    
    try {
        const response = await fetch('/api/documents/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('✅ Documento subido: ' + data.filename, 'success');
            fileInput.value = '';
            refreshDocuments();
        } else {
            showAlert('❌ ' + data.error, 'error');
        }
    } catch (error) {
        showAlert('❌ Error al subir documento', 'error');
    }
}

async function refreshDocuments() {
    const data = await fetchAPI('/api/documents/list');
    
    if (data && data.success) {
        documents = data.documents;
        displayDocuments();
        updateDocumentSelects();
    }
}

function displayDocuments() {
    const docsList = document.getElementById('documentsList');
    
    if (documents.length === 0) {
        docsList.innerHTML = '<p style="text-align: center; color: #666;">No hay documentos en este equipo</p>';
        return;
    }
    
    docsList.innerHTML = documents.map(doc => `
        <div class="document-item">
            <div class="document-info">
                <div class="document-name">${getDocIcon(doc.type)} ${doc.filename}</div>
                <div class="document-meta">${formatFileSize(doc.size)} - ${doc.type}</div>
            </div>
            <div class="document-actions">
                <button class="btn btn-secondary btn-small" onclick="downloadDocument('${doc.filename}')">
                    📥 Descargar
                </button>
            </div>
        </div>
    `).join('');
}

function getDocIcon(type) {
    const icons = {
        'original': '📄',
        'encrypted': '🔒',
        'key': '🔑',
        'signature': '✍️'
    };
    return icons[type] || '📄';
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function downloadDocument(filename) {
    window.location.href = `/api/documents/download/${filename}`;
}

function updateDocumentSelects() {
    // Actualizar todos los selectores de documentos
    const pdfDocs = documents.filter(d => d.filename.endsWith('.pdf') && !d.filename.startsWith('encrypted_'));
    const encryptedDocs = documents.filter(d => d.filename.endsWith('.enc'));
    const keyFiles = documents.filter(d => d.filename.endsWith('.key'));
    const wrappedKeys = documents.filter(d => d.filename.endsWith('.enc') && d.filename.includes('wrapped_key'));
    const signatureFiles = documents.filter(d => d.filename.endsWith('.json') && d.filename.startsWith('firma_'));
    
    // Para cifrado
    updateSelect('docToEncrypt', pdfDocs);
    updateSelect('keyFileToWrap', keyFiles);
    updateSelect('wrappedKeyFile', wrappedKeys);
    updateSelect('encryptedDocFile', encryptedDocs);
    updateSelect('keyFileForDecrypt', keyFiles);
    
    // Para firmas
    updateSelect('docToSign', pdfDocs.concat(documents.filter(d => d.filename.startsWith('decrypted_'))));
    updateSelect('docToVerify', pdfDocs.concat(documents.filter(d => d.filename.startsWith('decrypted_'))));
    updateSelect('signatureFiles', signatureFiles);
    
    // Recipientes de llaves (miembros del equipo)
    if (userInfo && userInfo.team_members) {
        const recipientSelect = document.getElementById('recipientForKey');
        if (recipientSelect) {
            recipientSelect.innerHTML = userInfo.team_members
                .filter(m => m !== userInfo.username)
                .map(m => `<option value="${m}">${m}</option>`)
                .join('');
        }
    }
}

function updateSelect(selectId, items) {
    const select = document.getElementById(selectId);
    if (!select) return;
    
    if (items.length === 0) {
        select.innerHTML = '<option value="">No hay archivos disponibles</option>';
    } else {
        select.innerHTML = items.map(item => 
            `<option value="${item.filename}">${item.filename}</option>`
        ).join('');
    }
}

// ============= CIFRADO Y DESCIFRADO =============

async function generateAESKey() {
    showAlert('🔄 Generando llave AES...', 'info');
    
    const data = await fetchAPI('/api/encrypt/generate_aes', { method: 'POST' });
    
    if (data && data.success) {
        document.getElementById('aesKeyText').value = data.aes_key;
        document.getElementById('aesKeyDisplay').style.display = 'block';
        showAlert('✅ Llave AES generada. Cópiala para usarla.', 'success');
    }
}

function copyAESKey() {
    const keyText = document.getElementById('aesKeyText');
    keyText.select();
    document.execCommand('copy');
    showAlert('✅ Llave AES copiada al portapapeles', 'success');
}

async function encryptDocument() {
    const filename = document.getElementById('docToEncrypt').value;
    const aesKey = document.getElementById('aesKeyForEncrypt').value.trim();
    
    if (!filename || !aesKey) {
        showAlert('⚠️ Selecciona documento e ingresa llave AES', 'error');
        return;
    }
    
    showAlert('🔒 Cifrando documento...', 'info');
    
    const data = await fetchAPI('/api/encrypt/document', {
        method: 'POST',
        body: JSON.stringify({ filename, aes_key: aesKey })
    });
    
    if (data && data.success) {
        showAlert(`✅ Documento cifrado: ${data.encrypted_file}`, 'success');
        document.getElementById('aesKeyForEncrypt').value = '';
        refreshDocuments();
    } else {
        showAlert('❌ Error al cifrar documento', 'error');
    }
}

async function wrapKey() {
    const keyFilename = document.getElementById('keyFileToWrap').value;
    const recipient = document.getElementById('recipientForKey').value;
    
    if (!keyFilename || !recipient) {
        showAlert('⚠️ Selecciona archivo de llave y destinatario', 'error');
        return;
    }
    
    showAlert('🔐 Cifrando llave para ' + recipient + '...', 'info');
    
    const data = await fetchAPI('/api/encrypt/wrap_key', {
        method: 'POST',
        body: JSON.stringify({ key_filename: keyFilename, recipient })
    });
    
    if (data && data.success) {
        showAlert(`✅ Llave cifrada para ${recipient}: ${data.wrapped_file}`, 'success');
        refreshDocuments();
    } else {
        showAlert('❌ Error al cifrar llave', 'error');
    }
}

async function unwrapKey() {
    const wrappedFilename = document.getElementById('wrappedKeyFile').value;
    
    if (!wrappedFilename) {
        showAlert('⚠️ Selecciona archivo de llave cifrada', 'error');
        return;
    }
    
    showAlert('🔓 Descifrando llave AES...', 'info');
    
    const data = await fetchAPI('/api/decrypt/unwrap_key', {
        method: 'POST',
        body: JSON.stringify({ wrapped_filename: wrappedFilename })
    });
    
    if (data && data.success) {
        showAlert(`✅ Llave recuperada: ${data.key_file}`, 'success');
        refreshDocuments();
    } else {
        showAlert('❌ Error al descifrar llave', 'error');
    }
}

async function decryptDocument() {
    const encryptedFilename = document.getElementById('encryptedDocFile').value;
    const keyFilename = document.getElementById('keyFileForDecrypt').value;
    
    if (!encryptedFilename || !keyFilename) {
        showAlert('⚠️ Selecciona documento cifrado y archivo de llave', 'error');
        return;
    }
    
    showAlert('🔓 Descifrando documento...', 'info');
    
    const data = await fetchAPI('/api/decrypt/document', {
        method: 'POST',
        body: JSON.stringify({ 
            encrypted_filename: encryptedFilename, 
            key_filename: keyFilename 
        })
    });
    
    if (data && data.success) {
        showAlert(`✅ Documento descifrado: ${data.decrypted_file}`, 'success');
        refreshDocuments();
    } else {
        showAlert('❌ Error al descifrar documento: ' + (data?.error || 'desconocido'), 'error');
    }
}

// ============= FIRMAS DIGITALES =============

async function signDocument() {
    const filename = document.getElementById('docToSign').value;
    
    if (!filename) {
        showAlert('⚠️ Selecciona un documento', 'error');
        return;
    }
    
    if (!userInfo.has_keys) {
        showAlert('⚠️ Debes generar tus llaves primero', 'error');
        return;
    }
    
    showAlert('✍️ Firmando documento...', 'info');
    
    const data = await fetchAPI('/api/sign/document', {
        method: 'POST',
        body: JSON.stringify({ filename })
    });
    
    if (data && data.success) {
        showAlert(`✅ Documento firmado: ${data.signature_file}`, 'success');
        refreshDocuments();
    } else {
        showAlert('❌ ' + (data?.error || 'Error al firmar documento'), 'error');
    }
}

async function verifySignatures() {
    const filename = document.getElementById('docToVerify').value;
    const signatureSelect = document.getElementById('signatureFiles');
    const signatureFiles = Array.from(signatureSelect.selectedOptions).map(o => o.value);
    
    if (!filename || signatureFiles.length === 0) {
        showAlert('⚠️ Selecciona documento y al menos una firma', 'error');
        return;
    }
    
    showAlert('🔍 Verificando firmas...', 'info');
    
    const data = await fetchAPI('/api/verify/signature', {
        method: 'POST',
        body: JSON.stringify({ filename, signature_files: signatureFiles })
    });
    
    if (data && data.success) {
        displayVerificationResults(data.results);
    } else {
        showAlert('❌ Error al verificar firmas', 'error');
    }
}

function displayVerificationResults(results) {
    const resultsDiv = document.getElementById('verificationResults');
    
    const validCount = results.filter(r => r.valid).length;
    const totalCount = results.length;
    
    let html = `
        <div class="card">
            <h3 class="card-title">📊 Resultados de Verificación</h3>
            <p style="margin-bottom: 15px;">
                <strong>${validCount}/${totalCount}</strong> firmas válidas
            </p>
    `;
    
    results.forEach(result => {
        const icon = result.valid ? '✅' : '❌';
        const color = result.valid ? '#28a745' : '#dc3545';
        
        html += `
            <div style="padding: 10px; margin-bottom: 10px; background: #f8f9fa; border-left: 4px solid ${color}; border-radius: 4px;">
                <strong>${icon} ${result.user || 'Desconocido'}</strong><br>
                <small style="color: #666;">
                    ${result.file}<br>
                    ${result.valid ? 'Firma válida' : (result.error || 'Firma inválida')}
                </small>
            </div>
        `;
    });
    
    html += '</div>';
    
    resultsDiv.innerHTML = html;
    
    if (validCount === totalCount) {
        showAlert('🎉 ¡Todas las firmas son válidas!', 'success');
    } else {
        showAlert(`⚠️ ${totalCount - validCount} firma(s) inválida(s)`, 'error');
    }
}
