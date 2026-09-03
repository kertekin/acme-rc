// ACME.rc Frontend Logic — Tauri v2
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// State Management
const state = {
  currentStep: 1,
  isStaging: false,
  challenges: [],
  createdDnsRecords: [],
  currentSessionCertResult: null,
  profiles: [],
  appSettings: null,
  historyItems: [],
  historyFilter: 'all',
  historySearch: '',
};




// DOM Elements
const elements = {
  // Navigation & Steps
  stepTabs: [
    document.getElementById('step-tab-1'),
    document.getElementById('step-tab-2'),
    document.getElementById('step-tab-3'),
  ],
  stepContents: [
    document.getElementById('step-content-1'),
    document.getElementById('step-content-2'),
    document.getElementById('step-content-3'),
  ],

  // Step 1 Form
  caSelect: document.getElementById('ca-select'),
  envProdBtn: document.getElementById('env-prod'),
  envStagingBtn: document.getElementById('env-staging'),
  customCaGroup: document.getElementById('custom-ca-group'),
  customCaUrl: document.getElementById('custom-ca-url'),
  accountEmail: document.getElementById('account-email'),
  eabSection: document.getElementById('eab-section'),
  eabRequiredBadge: document.getElementById('eab-required-badge'),
  eabHintText: document.getElementById('eab-hint-text'),
  tabEabManual: document.getElementById('tab-eab-manual'),
  tabEabGoogle: document.getElementById('tab-eab-google'),
  tabEabZerossl: document.getElementById('tab-eab-zerossl'),
  eabPanelGoogle: document.getElementById('eab-panel-google'),
  eabPanelZerossl: document.getElementById('eab-panel-zerossl'),
  gcpJsonFilename: document.getElementById('gcp-json-filename'),
  gcpJsonContent: document.getElementById('gcp-json-content'),
  btnBrowseGcpJson: document.getElementById('btn-browse-gcp-json'),
  btnFetchGoogleEab: document.getElementById('btn-fetch-google-eab'),
  zerosslApiKeyInput: document.getElementById('zerossl-api-key-input'),
  btnFetchZerosslEab: document.getElementById('btn-fetch-zerossl-eab'),
  eabKeyId: document.getElementById('eab-key-id'),
  eabHmacKey: document.getElementById('eab-hmac-key'),
  toggleHmacBtn: document.getElementById('toggle-hmac'),
  btnNextToStep2: document.getElementById('btn-next-to-step-2'),


  // Step 2 Form
  domainInput: document.getElementById('domain-input'),
  includeWww: document.getElementById('include-www'),
  includeWildcard: document.getElementById('include-wildcard'),
  keyTypeSelect: document.getElementById('key-type-select'),
  serverPresetSelect: document.getElementById('server-preset-select'),
  dnsProviderSelect: document.getElementById('dns-provider-select'),
  dnsServerUrlGroup: document.getElementById('dns-server-url-group'),
  dnsServerUrl: document.getElementById('dns-server-url'),
  dnsServerUrlLabel: document.getElementById('dns-server-url-label'),
  dnsTokenGroup: document.getElementById('dns-token-group'),
  dnsTokenLabel: document.getElementById('dns-token-label'),
  dnsApiToken: document.getElementById('dns-api-token'),
  toggleDnsToken: document.getElementById('toggle-dns-token'),
  dnsCustomConfigGroup: document.getElementById('dns-custom-config-group'),
  dnsCustomConfig: document.getElementById('dns-custom-config'),
  dnsCustomConfigLabel: document.getElementById('dns-custom-config-label'),
  outputDirInput: document.getElementById('output-dir-input'),
  btnBrowseDir: document.getElementById('btn-browse-dir'),

  deployTargetSelect: document.getElementById('deploy-target-select'),
  deployCustomPathGroup: document.getElementById('deploy-custom-path-group'),
  deployCustomPath: document.getElementById('deploy-custom-path'),
  deployCustomPathLabel: document.getElementById('deploy-custom-path-label'),
  deployHookCmdGroup: document.getElementById('deploy-hook-cmd-group'),
  deployHookCmd: document.getElementById('deploy-hook-cmd'),
  deploySshGroup: document.getElementById('deploy-ssh-group'),
  deploySshHost: document.getElementById('deploy-ssh-host'),
  deploySshPort: document.getElementById('deploy-ssh-port'),
  deploySshUser: document.getElementById('deploy-ssh-user'),
  deploySshKey: document.getElementById('deploy-ssh-key'),
  deploySshPass: document.getElementById('deploy-ssh-pass'),
  toggleSshPass: document.getElementById('toggle-ssh-pass'),
  btnBrowseSshKey: document.getElementById('btn-browse-ssh-key'),
  btnBackToStep1: document.getElementById('btn-back-to-step-1'),
  btnStartOrder: document.getElementById('btn-start-order'),
  certForm: document.getElementById('cert-form'),






  // Step 3 DNS & Finalize
  challengesList: document.getElementById('challenges-list'),
  btnCheckPropagation: document.getElementById('btn-check-propagation'),
  propSpinner: document.getElementById('prop-spinner'),
  resCloudflare: document.getElementById('res-cloudflare'),
  resGoogle: document.getElementById('res-google'),
  resQuad9: document.getElementById('res-quad9'),
  btnBackToStep2: document.getElementById('btn-back-to-step-2'),
  btnVerifyFinalize: document.getElementById('btn-verify-finalize'),

  // Terminal Logs
  terminalBody: document.getElementById('terminal-body'),
  btnCopyLogs: document.getElementById('btn-copy-logs'),
  btnClearLogs: document.getElementById('btn-clear-logs'),

  // Profiles & History
  profileSelect: document.getElementById('profile-select'),
  btnSaveProfile: document.getElementById('btn-save-profile'),
  btnDeleteProfile: document.getElementById('btn-delete-profile'),
  btnOpenHistory: document.getElementById('btn-open-history'),
  modalHistory: document.getElementById('modal-history'),
  btnCloseHistory: document.getElementById('btn-close-history'),
  historyTableBody: document.getElementById('history-table-body'),

  // Success Modal
  modalSuccess: document.getElementById('modal-success'),
  modalDomain: document.getElementById('modal-domain'),
  modalSans: document.getElementById('modal-sans'),
  modalCa: document.getElementById('modal-ca'),
  modalIssuedAt: document.getElementById('modal-issued-at'),
  btnOpenCertDir: document.getElementById('btn-open-cert-dir'),
  btnCloseSuccessModal: document.getElementById('btn-close-success-modal'),

  // Toast
  toastContainer: document.getElementById('toast-container'),
};

// ============================================================================
// Initialization & Event Listeners
// ============================================================================

async function initApp() {
  setupNavigation();
  setupFormControls();
  setupProfiles();
  setupHistoryModal();
  setupSettingsModal();
  setupAboutModal();
  setupThemeControls();
  setupLogListener();
  setupTerminalActions();
  await loadAppInfo();
  await loadAppSettings();
  resetFormToDefaults();
  await loadProfiles();
}



// ============================================================================
// Navigation & Steps Flow
// ============================================================================

function setupNavigation() {
  elements.btnNextToStep2.addEventListener('click', () => {
    if (validateStep1()) {
      goToStep(2);
    }
  });

  elements.btnBackToStep1.addEventListener('click', () => goToStep(1));
  elements.btnBackToStep2.addEventListener('click', () => goToStep(2));

  elements.certForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (state.currentStep === 2) {
      await handleStartOrder();
    }
  });

  elements.btnVerifyFinalize.addEventListener('click', handleVerifyAndFinalize);
}

function goToStep(step) {
  state.currentStep = step;

  elements.stepTabs.forEach((tab, i) => {
    const stepNum = i + 1;
    tab.classList.remove('active', 'completed');
    if (stepNum === step) {
      tab.classList.add('active');
    } else if (stepNum < step) {
      tab.classList.add('completed');
    }
  });

  elements.stepContents.forEach((card, i) => {
    card.style.display = i + 1 === step ? 'flex' : 'none';
  });
}

// ============================================================================
// Step 1: Form & CA Logic
// ============================================================================

function setupFormControls() {
  // CA Select change
  elements.caSelect.addEventListener('change', () => {
    updateCaFormState();
  });

  // Environment Toggles
  elements.envProdBtn.addEventListener('click', () => {
    state.isStaging = false;
    elements.envProdBtn.classList.add('active');
    elements.envStagingBtn.classList.remove('active');
  });

  elements.envStagingBtn.addEventListener('click', () => {
    if (elements.caSelect.value === 'ZeroSSL') {
      return;
    }
    state.isStaging = true;
    elements.envStagingBtn.classList.add('active');
    elements.envProdBtn.classList.remove('active');
  });



  // EAB Mode Switcher Tabs
  const setEabTab = (mode) => {
    elements.tabEabManual.classList.toggle('active', mode === 'manual');
    elements.tabEabGoogle.classList.toggle('active', mode === 'google');
    elements.tabEabZerossl.classList.toggle('active', mode === 'zerossl');

    elements.eabPanelGoogle.style.display = mode === 'google' ? 'flex' : 'none';
    elements.eabPanelZerossl.style.display = mode === 'zerossl' ? 'flex' : 'none';
  };

  elements.tabEabManual.addEventListener('click', () => setEabTab('manual'));
  elements.tabEabGoogle.addEventListener('click', () => setEabTab('google'));
  elements.tabEabZerossl.addEventListener('click', () => setEabTab('zerossl'));

  // Browse GCP Service Account JSON
  elements.btnBrowseGcpJson.addEventListener('click', async () => {
    try {
      const content = await invoke('select_json_file');
      if (content) {
        elements.gcpJsonContent.value = content;
        try {
          const parsed = JSON.parse(content);
          elements.gcpJsonFilename.value = parsed.client_email || parsed.project_id || 'service_account.json';
        } catch {
          elements.gcpJsonFilename.value = 'service_account.json';
        }
        showToast('Google Cloud Service Account JSON loaded.', 'info');
      }
    } catch (e) {
      showToast(`Failed to load JSON file: ${e}`, 'warn');
    }
  });

  // Fetch Google EAB from GCP API
  elements.btnFetchGoogleEab.addEventListener('click', async () => {
    const jsonStr = elements.gcpJsonContent.value.trim();
    if (!jsonStr) {
      showToast('Please select or paste your Google Cloud Service Account JSON first.', 'warn');
      return;
    }

    setButtonLoading(elements.btnFetchGoogleEab, true, 'Generating EAB via GCP...');
    try {
      const res = await invoke('fetch_google_eab', { saJson: jsonStr, isStaging: state.isStaging });
      elements.eabKeyId.value = res.key_id;
      elements.eabHmacKey.value = res.hmac_key;
      setEabTab('manual');
      const envName = state.isStaging ? 'Staging / Test' : 'Production';
      showToast(`Google Public CA (${envName}) EAB credentials generated and applied!`, 'success');
    } catch (e) {
      console.error('Fetch Google EAB error:', e);
      showToast(`Google Public CA EAB error: ${e}`, 'danger');
    } finally {
      setButtonLoading(elements.btnFetchGoogleEab, false, 'Fetch EAB from Google Cloud');
    }

  });

  // Fetch ZeroSSL EAB from ZeroSSL API
  elements.btnFetchZerosslEab.addEventListener('click', async () => {
    const apiKey = elements.zerosslApiKeyInput.value.trim();
    if (!apiKey) {
      showToast('Please enter your ZeroSSL API Access Key.', 'warn');
      return;
    }

    setButtonLoading(elements.btnFetchZerosslEab, true, 'Fetching EAB...');
    try {
      const res = await invoke('fetch_zerossl_eab', { apiKey });
      elements.eabKeyId.value = res.key_id;
      elements.eabHmacKey.value = res.hmac_key;
      setEabTab('manual');
      showToast('ZeroSSL EAB credentials retrieved and applied!', 'success');
    } catch (e) {
      console.error('Fetch ZeroSSL EAB error:', e);
      showToast(`ZeroSSL EAB error: ${e}`, 'danger');
    } finally {
      setButtonLoading(elements.btnFetchZerosslEab, false, 'Fetch from ZeroSSL');
    }
  });

  // Toggle HMAC Visibility
  elements.toggleHmacBtn.addEventListener('click', () => {
    const isPwd = elements.eabHmacKey.type === 'password';
    elements.eabHmacKey.type = isPwd ? 'text' : 'password';
  });

  // Directory Browser
  elements.btnBrowseDir.addEventListener('click', async () => {
    try {
      const selected = await invoke('select_directory');
      if (selected) {
        elements.outputDirInput.value = selected;
        showToast('Output directory selected.', 'info');
      }
    } catch (e) {
      console.warn('Dialog picker error:', e);
      showToast(`Directory picker failed: ${e}`, 'warn');
    }
  });

  // SSH Key File Browser
  if (elements.btnBrowseSshKey) {
    elements.btnBrowseSshKey.addEventListener('click', async () => {
      try {
        const selected = await invoke('select_key_file');
        if (selected) {
          elements.deploySshKey.value = selected;
          showToast('SSH private key selected.', 'info');
        }
      } catch (e) {
        console.warn('SSH key picker error:', e);
        showToast(`SSH key picker failed: ${e}`, 'warn');
      }
    });
  }


  // Smart Preset & Algorithm Dynamic Correlation
  let isInternalPresetChange = false;

  elements.keyTypeSelect.addEventListener('change', () => {
    if (isInternalPresetChange) return;
    const kt = elements.keyTypeSelect.value;
    const preset = elements.serverPresetSelect.value;

    if (kt.startsWith('ECDSA_')) {
      // ECC (P-256 / P-384) is incompatible with Plesk and cPanel mail/services
      if (preset === 'plesk' || preset === 'cpanel') {
        isInternalPresetChange = true;
        elements.serverPresetSelect.value = 'nginx';
        isInternalPresetChange = false;
      }
    }
  });

  elements.serverPresetSelect.addEventListener('change', () => {
    if (isInternalPresetChange) return;
    const preset = elements.serverPresetSelect.value;
    const kt = elements.keyTypeSelect.value;

    if (preset === 'plesk' || preset === 'cpanel') {
      // Plesk and cPanel require RSA for 100% web & mail compatibility
      if (kt.startsWith('ECDSA_')) {
        isInternalPresetChange = true;
        elements.keyTypeSelect.value = 'RSA_2048';
        isInternalPresetChange = false;
      }
    } else if (preset === 'nginx') {
      // Nginx / Apache / Docker are best optimized with modern ECDSA
      if (kt.startsWith('RSA_')) {
        isInternalPresetChange = true;
        elements.keyTypeSelect.value = 'ECDSA_P256';
        isInternalPresetChange = false;
      }
    }
  });

  // DNS Provider Switcher
  elements.dnsProviderSelect.addEventListener('change', updateDnsProviderState);


  // Toggle DNS API Token Visibility
  elements.toggleDnsToken.addEventListener('click', () => {
    const isPwd = elements.dnsApiToken.type === 'password';
    elements.dnsApiToken.type = isPwd ? 'text' : 'password';
  });

  // Toggle SSH Password Visibility
  if (elements.toggleSshPass) {
    elements.toggleSshPass.addEventListener('click', () => {
      const isPwd = elements.deploySshPass.type === 'password';
      elements.deploySshPass.type = isPwd ? 'text' : 'password';
    });
  }

  // Deploy Target Switcher
  elements.deployTargetSelect.addEventListener('change', updateDeployTargetState);

  updateCaFormState();
  updateDnsProviderState();
  updateDeployTargetState();
}


function updateDeployTargetState() {
  const t = elements.deployTargetSelect.value;

  if (t === 'none') {
    elements.deployCustomPathGroup.style.display = 'none';
    elements.deployHookCmdGroup.style.display = 'none';
    elements.deploySshGroup.style.display = 'none';
  } else if (t === 'local_nginx') {
    elements.deployCustomPathGroup.style.display = 'none';
    elements.deployHookCmdGroup.style.display = 'flex';
    elements.deployHookCmd.placeholder = 'systemctl reload nginx (or leave empty for default)';
    elements.deploySshGroup.style.display = 'none';
  } else if (t === 'local_apache') {
    elements.deployCustomPathGroup.style.display = 'none';
    elements.deployHookCmdGroup.style.display = 'flex';
    elements.deployHookCmd.placeholder = 'systemctl reload apache2 (or leave empty for default)';
    elements.deploySshGroup.style.display = 'none';
  } else if (t === 'local_plesk') {
    elements.deployCustomPathGroup.style.display = 'none';
    elements.deployHookCmdGroup.style.display = 'flex';
    elements.deployHookCmd.placeholder = 'plesk bin certificate ... (optional CLI hook)';
    elements.deploySshGroup.style.display = 'none';
  } else if (t === 'local_custom') {
    elements.deployCustomPathGroup.style.display = 'flex';
    elements.deployCustomPathLabel.textContent = 'Custom Target Path';
    elements.deployCustomPath.placeholder = '/var/www/my-app/ssl or /etc/ssl/{domain}';
    elements.deployHookCmdGroup.style.display = 'flex';
    elements.deployHookCmd.placeholder = 'docker restart webserver or custom shell command';
    elements.deploySshGroup.style.display = 'none';
  } else if (t === 'remote_ssh') {
    elements.deployCustomPathGroup.style.display = 'flex';
    elements.deployCustomPathLabel.textContent = 'Remote Destination Path';
    elements.deployCustomPath.placeholder = '/etc/nginx/ssl/{domain}';
    elements.deployHookCmdGroup.style.display = 'flex';
    elements.deployHookCmd.placeholder = 'systemctl reload nginx (executed on remote host)';
    elements.deploySshGroup.style.display = 'flex';
  }
}


function updateDnsProviderState() {
  const p = elements.dnsProviderSelect.value;
  if (p === 'manual') {
    elements.dnsServerUrlGroup.style.display = 'none';
    elements.dnsTokenGroup.style.display = 'none';
    elements.dnsCustomConfigGroup.style.display = 'none';
  } else if (p === 'plesk') {
    elements.dnsServerUrlGroup.style.display = 'flex';
    elements.dnsServerUrlLabel.textContent = 'Plesk Server URL';
    elements.dnsServerUrl.placeholder = 'https://panel.yourdomain.com:8443';
    elements.dnsTokenGroup.style.display = 'flex';
    elements.dnsTokenLabel.textContent = 'Plesk API Key (X-API-Key)';
    elements.dnsApiToken.placeholder = 'Enter Plesk API Key...';
    elements.dnsCustomConfigGroup.style.display = 'none';
  } else if (p === 'webhook') {
    elements.dnsServerUrlGroup.style.display = 'flex';
    elements.dnsServerUrlLabel.textContent = 'Create Record Endpoint (POST URL)';
    elements.dnsServerUrl.placeholder = 'https://api.yourdomain.com/dns/add';
    elements.dnsTokenGroup.style.display = 'flex';
    elements.dnsTokenLabel.textContent = 'Authorization Header (Optional)';
    elements.dnsApiToken.placeholder = 'Bearer token or API key...';
    elements.dnsCustomConfigGroup.style.display = 'flex';
    elements.dnsCustomConfigLabel.textContent = 'Delete Record Endpoint (Optional Cleanup)';
    elements.dnsCustomConfig.placeholder = 'https://api.yourdomain.com/dns/delete';
  } else {
    // Cloudflare, Hetzner, DigitalOcean
    elements.dnsServerUrlGroup.style.display = 'none';
    elements.dnsTokenGroup.style.display = 'flex';
    elements.dnsTokenLabel.textContent = 'API Token';
    elements.dnsCustomConfigGroup.style.display = 'none';

    if (p === 'cloudflare') {
      elements.dnsApiToken.placeholder = 'Cloudflare API Token (Zone.DNS Edit permission)...';
    } else if (p === 'hetzner') {
      elements.dnsApiToken.placeholder = 'Hetzner Auth-API-Token...';
    } else if (p === 'digitalocean') {
      elements.dnsApiToken.placeholder = 'DigitalOcean Personal Access Token...';
    }
  }
}



function updateCaFormState() {
  const ca = elements.caSelect.value;

  // Handle Staging Support by CA
  if (ca === 'ZeroSSL') {
    elements.envStagingBtn.disabled = true;
    elements.envStagingBtn.style.opacity = '0.4';
    elements.envStagingBtn.style.cursor = 'not-allowed';
    elements.envStagingBtn.title = 'ZeroSSL does not operate a separate staging environment (Production only)';
    if (state.isStaging) {
      state.isStaging = false;
      elements.envProdBtn.classList.add('active');
      elements.envStagingBtn.classList.remove('active');
    }
  } else {

    elements.envStagingBtn.disabled = false;
    elements.envStagingBtn.style.opacity = '1';
    elements.envStagingBtn.style.cursor = 'pointer';
    elements.envStagingBtn.title = 'Staging / Test Environment';
  }

  if (ca === 'Custom') {
    elements.customCaGroup.style.display = 'flex';
  } else {
    elements.customCaGroup.style.display = 'none';
  }


  // Let's Encrypt specific rules
  const wildcardContainer = document.getElementById('wildcard-toggle-container');
  const wildcardDesc = document.getElementById('wildcard-toggle-desc');

  elements.includeWildcard.disabled = false;
  if (wildcardContainer) wildcardContainer.style.opacity = '1';
  if (wildcardDesc) wildcardDesc.textContent = 'Covers all subdomains under this domain (requires DNS-01 verification).';

  if (ca === 'GoogleTrustServices') {
    elements.eabSection.style.display = 'flex';
    elements.eabRequiredBadge.style.display = 'inline-block';
    elements.eabRequiredBadge.textContent = 'Required for Google CA';
    elements.eabHintText.textContent = 'Enter your EAB keys manually or auto-generate them using your GCP Service Account JSON.';
    elements.tabEabGoogle.style.display = 'inline-flex';
    elements.tabEabZerossl.style.display = 'none';
  } else if (ca === 'ZeroSSL') {
    elements.eabSection.style.display = 'flex';
    elements.eabRequiredBadge.style.display = 'inline-block';
    elements.eabRequiredBadge.textContent = 'Required for ZeroSSL';
    elements.eabHintText.textContent = 'ZeroSSL requires EAB credentials. Enter them manually or fetch them automatically via ZeroSSL API Access Key.';
    elements.tabEabGoogle.style.display = 'none';
    elements.tabEabZerossl.style.display = 'inline-flex';
  } else {
    // Let's Encrypt or Custom
    elements.eabSection.style.display = 'none';
    elements.tabEabGoogle.style.display = 'none';
    elements.tabEabZerossl.style.display = 'none';
  }
}

function validateStep1() {
  const ca = elements.caSelect.value;

  if (ca === 'GoogleTrustServices' || ca === 'ZeroSSL') {
    const kid = elements.eabKeyId.value.trim();
    const hmac = elements.eabHmacKey.value.trim();
    if (!kid || !hmac) {
      const caName = ca === 'ZeroSSL' ? 'ZeroSSL' : 'Google Trust Services';
      showToast(`${caName} requires EAB Key ID and HMAC Key. Please provide or fetch them.`, 'warn');
      return false;
    }
  }

  if (ca === 'Custom' && !elements.customCaUrl.value.trim()) {
    showToast('Please provide a valid Custom ACME Directory URL', 'warn');
    return false;
  }

  return true;
}

// ============================================================================
// Step 2 & 3: Order Execution & Challenge Rendering
// ============================================================================

async function handleStartOrder() {
  const domain = elements.domainInput.value.trim();
  if (!domain) {
    showToast('Please enter a valid domain name', 'warn');
    return;
  }

  // Validate Remote SSH if selected
  if (elements.deployTargetSelect.value === 'remote_ssh') {
    const sshHost = elements.deploySshHost.value.trim();
    if (!sshHost) {
      showToast('Please enter your Remote SSH Server Host / IP', 'warn');
      elements.deploySshHost.focus();
      return;
    }
  }


  const req = {
    ca_type: elements.caSelect.value,
    is_staging: state.isStaging,
    email: elements.accountEmail.value.trim(),
    eab_key_id: elements.eabKeyId.value.trim() || null,
    eab_hmac_key: elements.eabHmacKey.value.trim() || null,
    custom_ca_url: elements.customCaUrl.value.trim() || null,
    domain: domain,
    include_www: elements.includeWww.checked,
    is_wildcard: elements.includeWildcard.checked,
    key_type: elements.keyTypeSelect.value,
    server_preset: elements.serverPresetSelect.value,
    output_dir: elements.outputDirInput.value.trim() || null,
    profile_name: elements.profileSelect.value || null,
  };



  setButtonLoading(elements.btnStartOrder, true, 'Connecting to CA...');

  try {
    const challenges = await invoke('start_acme_request', { request: req });
    state.challenges = challenges;
    state.createdDnsRecords = [];
    renderChallenges(challenges);
    goToStep(3);

    // Auto-provision DNS TXT Records if an API provider is configured
    const dnsProvider = elements.dnsProviderSelect.value;
    const dnsToken = elements.dnsApiToken.value.trim();
    const serverUrl = elements.dnsServerUrl.value.trim() || null;
    const customConfig = elements.dnsCustomConfig.value.trim() || null;

    if (dnsProvider !== 'manual' && (dnsToken || serverUrl)) {
      showToast(`Auto-provisioning DNS records via ${dnsProvider}...`, 'info');
      for (const ch of challenges) {
        try {
          const rec = await invoke('add_dns_txt_record', {
            provider: dnsProvider,
            token: dnsToken,
            host: ch.txt_host,
            value: ch.txt_value,
            serverUrl: serverUrl,
            customConfig: customConfig,
          });
          state.createdDnsRecords.push(rec);
        } catch (err) {
          console.warn('DNS API creation failed:', err);
          showToast(`Failed to add DNS record automatically: ${err}`, 'danger');
        }
      }

      if (state.createdDnsRecords.length > 0) {
        showToast(`Auto-created ${state.createdDnsRecords.length} DNS record(s) via ${dnsProvider}! Starting Auto-Pilot...`, 'success');
        startAutopilot(dnsProvider);
      }
    } else {
      stopAutopilot();
      showToast('DNS Challenge created! Please add TXT records.', 'success');
    }
  } catch (err) {
    console.error('ACME Start Error:', err);
    showToast(`Order Failed: ${err}`, 'danger');
    appendLog('ERROR', `Failed to start ACME order: ${err}`);
  } finally {
    setButtonLoading(elements.btnStartOrder, false, 'Generate DNS Challenges');
  }
}

let autopilotTimer = null;
let autopilotInterval = null;

function stopAutopilot() {
  if (autopilotTimer) clearTimeout(autopilotTimer);
  if (autopilotInterval) clearInterval(autopilotInterval);
  autopilotTimer = null;
  autopilotInterval = null;

  const banner = document.getElementById('autopilot-banner');
  const manualBox = document.getElementById('manual-propagation-box');
  const manualHost = document.getElementById('manual-propagation-host');
  const propResults = document.getElementById('propagation-results');

  if (banner) banner.style.display = 'none';
  if (manualBox && manualHost && propResults) {
    manualHost.appendChild(propResults);
    manualBox.style.display = 'flex';
  }

  const badge = document.getElementById('step-3-badge');
  if (badge) {
    badge.className = 'badge badge-accent';
    badge.textContent = 'Action Required';
  }
  const desc = document.getElementById('step-3-desc');
  if (desc) {
    desc.textContent = 'Add the following TXT record(s) to your DNS management panel (Cloudflare, GoDaddy, AWS Route53, Namecheap, etc.)';
  }

  // Re-enable manual verify button
  if (elements.btnVerifyFinalize) {
    elements.btnVerifyFinalize.disabled = false;
    elements.btnVerifyFinalize.style.opacity = '1';
    elements.btnVerifyFinalize.style.cursor = 'pointer';
    elements.btnVerifyFinalize.title = 'Verify DNS & Issue Certificate';
  }
}
async function startAutopilot(provider) {
  stopAutopilot();
  const banner = document.getElementById('autopilot-banner');
  const manualBox = document.getElementById('manual-propagation-box');
  const propResults = document.getElementById('propagation-results');
  const providerName = document.getElementById('autopilot-provider-name');
  const statusText = document.getElementById('autopilot-status-text');
  const countdownEl = document.getElementById('autopilot-countdown');
  const btnCancel = document.getElementById('btn-cancel-autopilot');
  const btnNow = document.getElementById('btn-autopilot-now');
  const badge = document.getElementById('step-3-badge');
  const desc = document.getElementById('step-3-desc');

  if (banner && propResults) {
    banner.appendChild(propResults);
    banner.style.display = 'flex';
  }
  if (manualBox) manualBox.style.display = 'none';
  if (providerName) providerName.textContent = `${provider.toUpperCase()} DNS API`;
  if (badge) {
    badge.className = 'badge badge-success';
    badge.textContent = '⚡ Auto-Pilot Active';
  }
  if (desc) {
    desc.textContent = `TXT challenge records were automatically published to ${provider.toUpperCase()}. ACME.rc is monitoring propagation and will automatically finalize your certificate.`;
  }

  // Lock manual button during Auto-Pilot to prevent race conditions
  if (elements.btnVerifyFinalize) {
    elements.btnVerifyFinalize.disabled = true;
    elements.btnVerifyFinalize.style.opacity = '0.5';
    elements.btnVerifyFinalize.style.cursor = 'not-allowed';
    elements.btnVerifyFinalize.title = 'Auto-Pilot is active. Issuance will trigger automatically when DNS is green.';
  }

  appendLog('INFO', `[Auto-Pilot] Records published to ${provider.toUpperCase()}. Monitoring live propagation across public resolvers...`);


  if (btnCancel) {
    btnCancel.onclick = () => {
      stopAutopilot();
      appendLog('INFO', '[Auto-Pilot] Automated flow paused by user. Manual verification enabled.');
      showToast('Auto-Pilot paused. You can verify manually.', 'info');
    };
  }

  if (btnNow) {
    btnNow.onclick = () => {
      stopAutopilot();
      handleVerifyAndFinalize();
    };
  }

  // Instant First Check on Start
  if (statusText) statusText.textContent = 'Performing initial DNS propagation check...';
  if (countdownEl) countdownEl.textContent = 'Scanning DNS...';

  const initialCheck = await handleCheckPropagation(true);
  if (initialCheck) {
    if (statusText) statusText.textContent = 'DNS confirmed instantly! Finalizing SSL certificate now...';
    if (countdownEl) countdownEl.textContent = 'Issuing Certificate...';
    appendLog('SUCCESS', '[Auto-Pilot] DNS records verified instantly on resolvers. Proceeding to finalize certificate with CA...');
    stopAutopilot();
    await handleVerifyAndFinalize();
    return;
  }

  let remaining = 6;
  if (countdownEl) countdownEl.textContent = `Auto-verifying in ${remaining}s...`;

  autopilotInterval = setInterval(() => {
    remaining -= 1;
    if (countdownEl) {
      countdownEl.textContent = `Auto-verifying in ${remaining}s...`;
    }
    if (remaining <= 0) {
      clearInterval(autopilotInterval);
      autopilotInterval = null;
      runAutopilotCheckAndFinalize(1);
    }
  }, 1000);
}

async function runAutopilotCheckAndFinalize(attempt = 1) {
  const statusText = document.getElementById('autopilot-status-text');
  const countdownEl = document.getElementById('autopilot-countdown');

  if (statusText) statusText.textContent = `Checking DNS propagation across public resolvers (Attempt ${attempt}/12)...`;
  if (countdownEl) countdownEl.textContent = 'Checking DNS resolvers...';

  try {
    const isPropagated = await handleCheckPropagation(true);
    if (isPropagated) {
      if (statusText) statusText.textContent = 'DNS confirmed (All Green)! Issuing and signing SSL certificate now...';
      if (countdownEl) countdownEl.textContent = 'Issuing Certificate...';
      appendLog('SUCCESS', '[Auto-Pilot] DNS propagation verified and green on resolvers. Proceeding to finalize certificate with CA...');
      stopAutopilot();
      await handleVerifyAndFinalize();
    } else {
      appendLog('INFO', `[Auto-Pilot] Waiting for DNS propagation to turn green (Attempt ${attempt}/12)...`);
      let remaining = 5;
      autopilotInterval = setInterval(() => {
        remaining -= 1;
        if (countdownEl) countdownEl.textContent = `Retrying check in ${remaining}s...`;
        if (remaining <= 0) {
          clearInterval(autopilotInterval);
          autopilotInterval = null;
          runAutopilotCheckAndFinalize(attempt + 1);
        }
      }, 1000);
    }
  } catch (err) {
    console.warn('Autopilot check failed:', err);
    appendLog('WARN', `[Auto-Pilot] Propagation check error: ${err}. Retrying in 5 seconds...`);
    let remaining = 5;
    autopilotInterval = setInterval(() => {
      remaining -= 1;
      if (countdownEl) countdownEl.textContent = `Retrying check in ${remaining}s...`;
      if (remaining <= 0) {
        clearInterval(autopilotInterval);
        autopilotInterval = null;
        runAutopilotCheckAndFinalize(attempt + 1);
      }
    }, 1000);
  }
}


function renderChallenges(challenges) {
  elements.challengesList.innerHTML = '';

  challenges.forEach((ch, idx) => {
    const card = document.createElement('div');
    card.className = 'challenge-card';
    card.innerHTML = `
      <div class="challenge-card-header">
        <div class="challenge-domain">Domain: ${escapeHtml(ch.domain)}</div>
        <span class="badge badge-primary">Record #${idx + 1}</span>
      </div>

      <div class="challenge-fields">
        <div class="challenge-field">
          <label>Record Type</label>
          <div class="field-value-copy">
            <span class="value-text font-mono">${escapeHtml(ch.txt_type || 'TXT')}</span>
            <button type="button" class="btn-copy" data-copy="${escapeHtml(ch.txt_type || 'TXT')}" title="Copy Record Type">Copy</button>
          </div>
        </div>

        <div class="challenge-field">
          <label>Host / Name</label>
          <div class="field-value-copy">
            <span class="value-text font-mono">${escapeHtml(ch.txt_host)}</span>
            <button type="button" class="btn-copy" data-copy="${escapeHtml(ch.txt_host)}" title="Copy Host">Copy</button>
          </div>
        </div>

        <div class="challenge-field full-width">
          <label>TXT Value</label>
          <div class="field-value-copy">
            <span class="value-text font-mono txt-val">${escapeHtml(ch.txt_value)}</span>
            <button type="button" class="btn-copy" data-copy="${escapeHtml(ch.txt_value)}" title="Copy Value">Copy</button>
          </div>
        </div>
      </div>
    `;
    elements.challengesList.appendChild(card);
  });

  // Attach copy listeners
  elements.challengesList.querySelectorAll('.btn-copy').forEach((btn) => {
    btn.addEventListener('click', () => {
      const textToCopy = btn.getAttribute('data-copy');
      copyToClipboard(textToCopy, btn);
    });
  });

  // Setup Propagation Button & Initial Container Placement
  elements.btnCheckPropagation.onclick = () => handleCheckPropagation(false);

  const propResults = document.getElementById('propagation-results');
  const manualBox = document.getElementById('manual-propagation-box');
  const manualHost = document.getElementById('manual-propagation-host');
  const banner = document.getElementById('autopilot-banner');

  if (state.dnsProvider === 'manual') {
    if (banner) banner.style.display = 'none';
    if (manualBox && manualHost && propResults) {
      manualHost.appendChild(propResults);
      manualBox.style.display = 'flex';
    }
  } else {
    if (manualBox) manualBox.style.display = 'none';
    if (banner && propResults) {
      banner.appendChild(propResults);
    }
  }
}

async function handleCheckPropagation(isSilent = false) {
  if (!state.challenges || state.challenges.length === 0) return false;

  elements.propSpinner.style.display = 'inline-block';
  elements.btnCheckPropagation.disabled = true;

  // Set visual scanning indicator on cards
  [elements.resCloudflare, elements.resGoogle, elements.resQuad9].forEach((el) => {
    if (el) {
      const statusEl = el.querySelector('.res-status');
      if (statusEl && !statusEl.classList.contains('status-matched')) {
        statusEl.className = 'res-status status-pending';
        statusEl.textContent = 'Checking...';
      }
    }
  });

  try {
    let allChallengesPassed = true;
    let anyChallengeDetected = false;

    const resolverStats = {
      Cloudflare: { matched: 0, total: 0, lastResult: null },
      Google: { matched: 0, total: 0, lastResult: null },
      Quad9: { matched: 0, total: 0, lastResult: null },
    };

    for (let i = 0; i < state.challenges.length; i++) {
      const ch = state.challenges[i];
      const report = await invoke('check_dns', {
        txtHost: ch.txt_host,
        expectedValue: ch.txt_value,
      });

      for (const r of report.results || []) {
        const name = r.server_name || '';
        let key = 'Quad9';
        if (name.includes('Cloudflare')) key = 'Cloudflare';
        else if (name.includes('Google')) key = 'Google';

        resolverStats[key].total += 1;
        if (r.matched) resolverStats[key].matched += 1;
        resolverStats[key].lastResult = r;
      }

      if (!report.fully_propagated) {
        allChallengesPassed = false;
      }
      if (report.results && report.results.some((r) => r.matched)) {
        anyChallengeDetected = true;
      }
    }

    // Update resolver status UI elements dynamically
    updateResolverStatus(elements.resCloudflare, resolverStats.Cloudflare);
    updateResolverStatus(elements.resGoogle, resolverStats.Google);
    updateResolverStatus(elements.resQuad9, resolverStats.Quad9);

    // Check if resolvers have fully matched
    const cfPassed = resolverStats.Cloudflare.matched === resolverStats.Cloudflare.total && resolverStats.Cloudflare.total > 0;
    const gPassed = resolverStats.Google.matched === resolverStats.Google.total && resolverStats.Google.total > 0;
    const isFullyPropagated = (cfPassed && gPassed) || allChallengesPassed;

    if (isFullyPropagated) {
      if (!isSilent) showToast('All DNS challenge records verified on public resolvers!', 'success');
      return true;
    } else {
      if (!isSilent) showToast('DNS not yet propagated everywhere. Please wait a moment.', 'warn');
      return false;
    }
  } catch (err) {
    if (!isSilent) showToast(`Propagation check error: ${err}`, 'danger');
    return false;
  } finally {
    elements.propSpinner.style.display = 'none';
    elements.btnCheckPropagation.disabled = false;
  }
}


function updateResolverStatus(element, stat) {
  if (!element) return;
  const statusEl = element.querySelector('.res-status');
  if (!statusEl) return;

  if (!stat || stat.total === 0) {
    statusEl.className = 'res-status status-pending';
    statusEl.textContent = 'Not Checked';
    return;
  }

  if (stat.matched === stat.total) {
    statusEl.className = 'res-status status-matched';
    statusEl.textContent = 'Propagated (Matched)';
  } else if (stat.matched > 0) {
    statusEl.className = 'res-status status-matched';
    statusEl.textContent = `Partial (${stat.matched}/${stat.total} Matched)`;
  } else if (stat.lastResult && stat.lastResult.records && stat.lastResult.records.length > 0) {
    statusEl.className = 'res-status status-failed';
    statusEl.textContent = 'Different TXT Found';
  } else {
    statusEl.className = 'res-status status-failed';
    statusEl.textContent = 'Not detected yet';
  }
}

async function handleVerifyAndFinalize() {
  setButtonLoading(elements.btnVerifyFinalize, true, 'Validating & Issuing...');

  try {
    const certResult = await invoke('finalize_certificate');
    state.currentSessionCertResult = certResult;

    // Automatic DNS Cleanup for auto-provisioned records
    const dnsProvider = elements.dnsProviderSelect.value;
    const dnsToken = elements.dnsApiToken.value.trim();
    const serverUrl = elements.dnsServerUrl.value.trim() || null;
    const customConfig = elements.dnsCustomConfig.value.trim() || null;

    if (state.createdDnsRecords && state.createdDnsRecords.length > 0) {
      showToast('Cleaning up temporary DNS TXT records...', 'info');
      for (const rec of state.createdDnsRecords) {
        try {
          await invoke('delete_dns_txt_record', {
            provider: rec.provider,
            token: dnsToken,
            host: rec.host,
            recordId: rec.record_id,
            zoneId: rec.zone_id || null,
            serverUrl: serverUrl,
            customConfig: customConfig,
          });
        } catch (cleanupErr) {
          console.warn('DNS cleanup error:', cleanupErr);
        }
      }
      state.createdDnsRecords = [];
    }

    // Trigger Auto-Deployment if configured

    const deployTarget = elements.deployTargetSelect.value;
    if (deployTarget !== 'none') {
      showToast(`Auto-deploying to ${deployTarget}...`, 'info');
      try {
        const deployConfig = {
          target: deployTarget,
          custom_path: elements.deployCustomPath.value.trim() || null,
          hook_cmd: elements.deployHookCmd.value.trim() || null,
          ssh_host: elements.deploySshHost.value.trim() || null,
          ssh_port: parseInt(elements.deploySshPort.value, 10) || 22,
          ssh_user: elements.deploySshUser.value.trim() || 'root',
          ssh_key: elements.deploySshKey.value.trim() || null,
          ssh_pass: elements.deploySshPass ? elements.deploySshPass.value.trim() || null : null,
        };
        const deploySummary = await invoke('deploy_certificate', {
          domain: certResult.domain,
          certDir: certResult.output_dir,
          config: deployConfig,
        });
        showToast(`Deployment success: ${deploySummary}`, 'success');
      } catch (deployErr) {
        console.warn('Auto-deploy warning:', deployErr);
        showToast(`Auto-deploy: ${deployErr}`, 'warn');
      }
    }

    showSuccessModal(certResult);
    showToast('Certificate successfully issued and saved!', 'success');
  } catch (err) {
    console.error('Finalize error:', err);
    showToast(`Verification Failed: ${err}`, 'danger');
    appendLog('ERROR', `Certificate generation failed: ${err}`);
  } finally {
    setButtonLoading(elements.btnVerifyFinalize, false, 'Verify DNS & Issue Certificate');
  }
}




function showSuccessModal(cert) {
  elements.modalDomain.textContent = cert.domain;
  elements.modalSans.textContent = cert.sans.join(', ');
  elements.modalCa.textContent = `${cert.ca_used} ${cert.is_staging ? '(Staging)' : '(Production)'}`;
  elements.modalIssuedAt.textContent = new Date(cert.issued_at).toLocaleString();

  const modalOutputDir = document.getElementById('modal-output-dir');
  const btnCopyModalDir = document.getElementById('btn-copy-modal-dir');

  if (modalOutputDir) {
    modalOutputDir.textContent = cert.output_dir;
  }

  if (btnCopyModalDir) {
    btnCopyModalDir.onclick = () => {
      copyToClipboard(cert.output_dir, btnCopyModalDir);
    };
  }

  elements.btnOpenCertDir.onclick = async () => {
    try {
      await invoke('open_folder', { path: cert.output_dir });
    } catch (e) {
      showToast(`Could not open folder: ${e}`, 'warn');
    }
  };

  elements.btnCloseSuccessModal.onclick = () => {
    elements.modalSuccess.style.display = 'none';
    goToStep(1);
  };

  elements.modalSuccess.style.display = 'flex';
}


// ============================================================================
// Profile Management (SQLite)
// ============================================================================

function setupProfiles() {
  const modalSaveProfile = document.getElementById('modal-save-profile');
  const btnCloseSaveProfile = document.getElementById('btn-close-save-profile');
  const btnCancelSaveProfile = document.getElementById('btn-cancel-save-profile');
  const formSaveProfile = document.getElementById('form-save-profile');
  const profileNameInput = document.getElementById('profile-name-input');

  // Profile Dropdown Selection
  elements.profileSelect.addEventListener('change', () => {
    const selectedName = elements.profileSelect.value;
    if (!selectedName) {
      // "+ New Profile..." selected -> Reset form to defaults
      resetFormToDefaults();
      elements.btnDeleteProfile.style.display = 'none';
      showToast('Switched to new profile mode.', 'info');
      return;
    }

    const profile = state.profiles.find((p) => p.profile_name === selectedName);
    if (profile) {
      applyProfile(profile);
      elements.btnDeleteProfile.style.display = 'inline-flex';
    }
  });

  // Open Save Profile Modal
  elements.btnSaveProfile.addEventListener('click', () => {
    const currentSelected = elements.profileSelect.value;
    const currentDomain = elements.domainInput.value.trim();

    if (currentSelected) {
      profileNameInput.value = currentSelected;
    } else if (currentDomain) {
      profileNameInput.value = currentDomain;
    } else {
      profileNameInput.value = 'default_profile';
    }

    modalSaveProfile.style.display = 'flex';
    setTimeout(() => profileNameInput.focus(), 100);
  });

  const closeSaveModal = () => {
    modalSaveProfile.style.display = 'none';
  };

  btnCloseSaveProfile.addEventListener('click', closeSaveModal);
  btnCancelSaveProfile.addEventListener('click', closeSaveModal);

  // Handle Form Submit for Save Profile
  formSaveProfile.addEventListener('submit', async (e) => {
    e.preventDefault();
    const profileName = profileNameInput.value.trim();
    if (!profileName) return;

    const profile = {
      id: null,
      profile_name: profileName,
      ca_type: elements.caSelect.value,
      is_staging: state.isStaging,
      email: elements.accountEmail.value.trim(),
      eab_key_id: elements.eabKeyId.value.trim() || null,
      eab_hmac_key: elements.eabHmacKey.value.trim() || null,
      gcp_sa_json: elements.gcpJsonContent.value.trim() || null,
      zerossl_api_key: elements.zerosslApiKeyInput.value.trim() || null,
      custom_ca_url: elements.customCaUrl.value.trim() || null,
      domain: elements.domainInput.value.trim(),
      include_www: elements.includeWww.checked,
      is_wildcard: elements.includeWildcard.checked,
      key_type: elements.keyTypeSelect.value,
      server_preset: elements.serverPresetSelect.value,
      dns_provider: elements.dnsProviderSelect.value,
      dns_api_token: elements.dnsApiToken.value.trim() || null,
      dns_server_url: elements.dnsServerUrl.value.trim() || null,
      dns_custom_config: elements.dnsCustomConfig.value.trim() || null,
      deploy_target: elements.deployTargetSelect.value,
      deploy_custom_path: elements.deployCustomPath.value.trim() || null,
      deploy_hook_cmd: elements.deployHookCmd.value.trim() || null,
      deploy_ssh_host: elements.deploySshHost.value.trim() || null,
      deploy_ssh_port: parseInt(elements.deploySshPort.value, 10) || 22,
      deploy_ssh_user: elements.deploySshUser.value.trim() || null,
      deploy_ssh_key: elements.deploySshKey.value.trim() || null,
      deploy_ssh_pass: elements.deploySshPass ? elements.deploySshPass.value.trim() || null : null,
      output_dir: elements.outputDirInput.value.trim() || null,
      updated_at: null,
    };


    try {
      await invoke('save_profile', { profile });
      closeSaveModal();
      showToast(`Profile "${profileName}" saved successfully!`, 'success');
      await loadProfiles();
      elements.profileSelect.value = profileName;
      elements.btnDeleteProfile.style.display = 'inline-flex';
    } catch (err) {
      showToast(`Failed to save profile: ${err}`, 'danger');
    }
  });

  // Handle Delete Profile
  elements.btnDeleteProfile.addEventListener('click', async () => {
    const selectedName = elements.profileSelect.value;
    if (!selectedName) return;

    if (confirm(`Are you sure you want to delete profile "${selectedName}"?`)) {
      try {
        await invoke('delete_profile', { name: selectedName });
        showToast(`Profile "${selectedName}" deleted.`, 'info');
        await loadProfiles();
        elements.profileSelect.value = '';
        elements.btnDeleteProfile.style.display = 'none';
        resetFormToDefaults();
      } catch (e) {
        showToast(`Delete failed: ${e}`, 'danger');
      }
    }
  });
}

function resetFormToDefaults() {
  const s = state.appSettings || {};

  elements.caSelect.value = s.default_ca || 'GoogleTrustServices';
  state.isStaging = !!s.default_is_staging;

  if (state.isStaging) {
    elements.envStagingBtn.classList.add('active');
    elements.envProdBtn.classList.remove('active');
  } else {
    elements.envProdBtn.classList.add('active');
    elements.envStagingBtn.classList.remove('active');
  }

  elements.accountEmail.value = s.default_email || '';
  elements.eabKeyId.value = '';
  elements.eabHmacKey.value = '';
  elements.gcpJsonContent.value = s.global_gcp_sa_json || '';
  if (s.global_gcp_sa_json) {
    try {
      const parsed = JSON.parse(s.global_gcp_sa_json);
      elements.gcpJsonFilename.value = parsed.client_email || parsed.project_id || 'saved_service_account.json';
    } catch {
      elements.gcpJsonFilename.value = 'saved_service_account.json';
    }
  } else {
    elements.gcpJsonFilename.value = '';
  }

  elements.zerosslApiKeyInput.value = s.global_zerossl_api_key || '';
  elements.customCaUrl.value = '';
  elements.domainInput.value = '';
  elements.includeWww.checked = true;
  elements.includeWildcard.checked = true;
  elements.keyTypeSelect.value = s.default_key_type || 'ECDSA_P256';
  elements.serverPresetSelect.value = s.default_server_preset || 'all';
  elements.dnsProviderSelect.value = s.default_dns_provider || 'manual';
  elements.dnsApiToken.value = s.default_dns_api_token || '';
  elements.dnsServerUrl.value = s.default_dns_server_url || '';
  elements.dnsCustomConfig.value = s.default_dns_custom_config || '';
  elements.deployTargetSelect.value = s.default_deploy_target || 'none';
  elements.deployCustomPath.value = s.default_deploy_custom_path || '';
  elements.deployHookCmd.value = s.default_deploy_hook_cmd || '';
  elements.deploySshHost.value = '';
  elements.deploySshPort.value = '22';
  elements.deploySshUser.value = 'root';
  elements.deploySshKey.value = '';
  elements.outputDirInput.value = s.default_output_dir || '';

  updateCaFormState();
  updateDnsProviderState();
  updateDeployTargetState();
}

async function loadAppSettings() {
  try {
    const s = await invoke('get_app_settings');
    state.appSettings = s;
    if (s.theme_mode) {
      applyTheme(s.theme_mode);
    }
  } catch (e) {
    console.warn('Failed to load app settings:', e);
  }
}

async function loadAppInfo() {
  try {
    const info = await invoke('get_app_info');
    document.querySelectorAll('.badge-version').forEach((el) => {
      el.textContent = `v${info.version}`;
    });
    const aboutVer = document.getElementById('about-app-version');
    if (aboutVer) {
      aboutVer.textContent = info.full_version || `v${info.version}`;
    }
  } catch (e) {
    console.warn('Could not load app info:', e);
  }
}

function applyTheme(theme) {
  const isLight = theme === 'light';
  document.body.className = isLight ? 'light-theme' : 'dark-theme';

  const iconDark = document.getElementById('theme-icon-dark');
  const iconLight = document.getElementById('theme-icon-light');
  if (iconDark && iconLight) {
    iconDark.style.display = isLight ? 'inline' : 'none';
    iconLight.style.display = isLight ? 'none' : 'inline';
  }

  localStorage.setItem('acmerc_theme', theme);
}

function setupThemeControls() {
  const savedTheme = localStorage.getItem('acmerc_theme') || 'dark';
  applyTheme(savedTheme);

  const btnToggle = document.getElementById('btn-toggle-theme');
  if (btnToggle) {
    btnToggle.addEventListener('click', async () => {
      const current = document.body.classList.contains('light-theme') ? 'light' : 'dark';
      const nextTheme = current === 'light' ? 'dark' : 'light';
      applyTheme(nextTheme);

      if (state.appSettings) {
        state.appSettings.theme_mode = nextTheme;
        try {
          await invoke('save_app_settings', { settings: state.appSettings });
        } catch (e) {
          console.warn('Could not save theme:', e);
        }
      }
    });
  }
}

function setupAboutModal() {
  const btnOpen = document.getElementById('btn-open-about');
  const modal = document.getElementById('modal-about');
  const btnClose = document.getElementById('btn-close-about');
  const btnOk = document.getElementById('btn-about-ok');

  if (btnOpen && modal) {
    btnOpen.addEventListener('click', () => {
      modal.style.display = 'flex';
    });
  }

  const closeModal = () => {
    if (modal) modal.style.display = 'none';
  };

  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (btnOk) btnOk.addEventListener('click', closeModal);
}

function setupSettingsModal() {
  const btnOpenSettings = document.getElementById('btn-open-settings');
  const modalSettings = document.getElementById('modal-settings');
  const btnCloseSettings = document.getElementById('btn-close-settings');
  const btnCancelSettings = document.getElementById('btn-cancel-settings');
  const formSettings = document.getElementById('form-settings');
  const btnResetFactory = document.getElementById('btn-reset-factory-settings');

  // Input Fields
  const setDefaultCa = document.getElementById('set-default-ca');
  const setDefaultStaging = document.getElementById('set-default-staging');
  const setDefaultEmail = document.getElementById('set-default-email');
  const setDefaultKeyType = document.getElementById('set-default-key-type');
  const setDefaultServerPreset = document.getElementById('set-default-server-preset');
  const setDefaultOutputDir = document.getElementById('set-default-output-dir');
  const setDefaultDnsProvider = document.getElementById('set-default-dns-provider');
  const setDefaultDnsToken = document.getElementById('set-default-dns-token');
  const setDefaultDnsServerUrl = document.getElementById('set-default-dns-server-url');
  const setDefaultDeployTarget = document.getElementById('set-default-deploy-target');
  const setDefaultDeployHook = document.getElementById('set-default-deploy-hook');
  const setThemeMode = document.getElementById('set-theme-mode');

  const populateSettingsModal = (s) => {
    setDefaultCa.value = s.default_ca || 'GoogleTrustServices';
    setDefaultStaging.value = s.default_is_staging ? 'true' : 'false';
    setDefaultEmail.value = s.default_email || '';
    setDefaultKeyType.value = s.default_key_type || 'ECDSA_P256';
    setDefaultServerPreset.value = s.default_server_preset || 'all';
    setDefaultOutputDir.value = s.default_output_dir || '';
    setDefaultDnsProvider.value = s.default_dns_provider || 'manual';
    setDefaultDnsToken.value = s.default_dns_api_token || '';
    setDefaultDnsServerUrl.value = s.default_dns_server_url || '';
    setDefaultDeployTarget.value = s.default_deploy_target || 'none';
    setDefaultDeployHook.value = s.default_deploy_hook_cmd || '';
    if (setThemeMode) setThemeMode.value = s.theme_mode || 'dark';
  };

  btnOpenSettings.addEventListener('click', () => {
    const s = state.appSettings || {};
    populateSettingsModal(s);
    modalSettings.style.display = 'flex';
  });

  const closeSettings = () => {
    modalSettings.style.display = 'none';
  };

  btnCloseSettings.addEventListener('click', closeSettings);
  btnCancelSettings.addEventListener('click', closeSettings);

  formSettings.addEventListener('submit', async (e) => {
    e.preventDefault();
    const newTheme = setThemeMode ? setThemeMode.value : 'dark';
    applyTheme(newTheme);

    const newSettings = {
      default_ca: setDefaultCa.value,
      default_is_staging: setDefaultStaging.value === 'true',
      default_email: setDefaultEmail.value.trim(),
      default_key_type: setDefaultKeyType.value,
      default_server_preset: setDefaultServerPreset.value,
      default_dns_provider: setDefaultDnsProvider.value,
      default_dns_api_token: setDefaultDnsToken.value.trim() || null,
      default_dns_server_url: setDefaultDnsServerUrl.value.trim() || null,
      default_dns_custom_config: null,
      default_deploy_target: setDefaultDeployTarget.value,
      default_deploy_custom_path: null,
      default_deploy_hook_cmd: setDefaultDeployHook.value.trim() || null,
      default_output_dir: setDefaultOutputDir.value.trim() || null,
      global_gcp_sa_json: state.appSettings?.global_gcp_sa_json || null,
      global_zerossl_api_key: state.appSettings?.global_zerossl_api_key || null,
      theme_mode: newTheme,
    };

    try {
      await invoke('save_app_settings', { settings: newSettings });
      state.appSettings = newSettings;
      closeSettings();
      showToast('Global settings saved successfully!', 'success');

      // If currently on "+ New Profile", refresh active form defaults
      if (!elements.profileSelect.value) {
        resetFormToDefaults();
      }
    } catch (err) {
      showToast(`Failed to save settings: ${err}`, 'danger');
    }
  });

  btnResetFactory.addEventListener('click', async () => {
    if (confirm('Reset all global settings back to factory defaults?')) {
      const factory = {
        default_ca: 'GoogleTrustServices',
        default_is_staging: false,
        default_email: '',
        default_key_type: 'ECDSA_P256',
        default_server_preset: 'all',
        default_dns_provider: 'manual',
        default_dns_api_token: null,
        default_dns_server_url: null,
        default_dns_custom_config: null,
        default_deploy_target: 'none',
        default_deploy_custom_path: null,
        default_deploy_hook_cmd: null,
        default_output_dir: null,
        global_gcp_sa_json: null,
        global_zerossl_api_key: null,
        theme_mode: 'dark',
      };
      try {
        await invoke('save_app_settings', { settings: factory });
        state.appSettings = factory;
        applyTheme('dark');
        populateSettingsModal(factory);
        showToast('Restored to factory defaults.', 'info');
        if (!elements.profileSelect.value) {
          resetFormToDefaults();
        }
      } catch (err) {
        showToast(`Reset failed: ${err}`, 'danger');
      }
    }
  });
}



async function loadProfiles() {
  try {
    const list = await invoke('get_profiles');
    state.profiles = list;

    elements.profileSelect.innerHTML = '<option value="">+ New Profile...</option>';
    list.forEach((p) => {
      const opt = document.createElement('option');
      opt.value = p.profile_name;
      opt.textContent = `${p.profile_name} (${p.domain || 'no domain'})`;
      elements.profileSelect.appendChild(opt);
    });
  } catch (e) {
    console.warn('Could not load profiles:', e);
  }
}

function applyProfile(p) {
  elements.caSelect.value = p.ca_type || 'GoogleTrustServices';
  state.isStaging = !!p.is_staging;

  if (state.isStaging) {
    elements.envStagingBtn.classList.add('active');
    elements.envProdBtn.classList.remove('active');
  } else {
    elements.envProdBtn.classList.add('active');
    elements.envStagingBtn.classList.remove('active');
  }

  elements.accountEmail.value = p.email || '';
  elements.eabKeyId.value = p.eab_key_id || '';
  elements.eabHmacKey.value = p.eab_hmac_key || '';
  elements.gcpJsonContent.value = p.gcp_sa_json || '';
  if (p.gcp_sa_json) {
    try {
      const parsed = JSON.parse(p.gcp_sa_json);
      elements.gcpJsonFilename.value = parsed.client_email || parsed.project_id || 'saved_service_account.json';
    } catch {
      elements.gcpJsonFilename.value = 'saved_service_account.json';
    }
  } else {
    elements.gcpJsonFilename.value = '';
  }

  elements.zerosslApiKeyInput.value = p.zerossl_api_key || '';
  elements.customCaUrl.value = p.custom_ca_url || '';
  elements.domainInput.value = p.domain || '';
  elements.includeWww.checked = p.include_www !== false;
  elements.includeWildcard.checked = p.is_wildcard !== false;
  elements.keyTypeSelect.value = p.key_type || 'ECDSA_P256';
  elements.serverPresetSelect.value = p.server_preset || 'all';
  elements.dnsProviderSelect.value = p.dns_provider || 'manual';
  elements.dnsApiToken.value = p.dns_api_token || '';
  elements.dnsServerUrl.value = p.dns_server_url || '';
  elements.dnsCustomConfig.value = p.dns_custom_config || '';
  elements.deployTargetSelect.value = p.deploy_target || 'none';
  elements.deployCustomPath.value = p.deploy_custom_path || '';
  elements.deployHookCmd.value = p.deploy_hook_cmd || '';
  elements.deploySshHost.value = p.deploy_ssh_host || '';
  elements.deploySshPort.value = p.deploy_ssh_port ? String(p.deploy_ssh_port) : '22';
  elements.deploySshUser.value = p.deploy_ssh_user || 'root';
  elements.deploySshKey.value = p.deploy_ssh_key || '';
  if (elements.deploySshPass) {
    elements.deploySshPass.value = p.deploy_ssh_pass || '';
  }
  elements.outputDirInput.value = p.output_dir || '';

  updateCaFormState();
  updateDnsProviderState();
  updateDeployTargetState();

  showToast(`Loaded profile "${p.profile_name}"`, 'info');
}






// ============================================================================
// Active Domains & Certificates Modal (History & Expiration Manager)
// ============================================================================

function getRemainingDaysInfo(expiresAtStr) {
  if (!expiresAtStr) {
    return { text: 'N/A', badgeClass: 'badge-muted', days: null, status: 'unknown' };
  }

  const now = new Date();
  const exp = new Date(expiresAtStr);
  const diffMs = exp.getTime() - now.getTime();
  const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays < 0) {
    return {
      text: `Expired (${Math.abs(diffDays)}d ago)`,
      badgeClass: 'badge-danger',
      days: diffDays,
      status: 'expired',
    };
  } else if (diffDays === 0) {
    return {
      text: 'Expires Today',
      badgeClass: 'badge-danger',
      days: 0,
      status: 'warning',
    };
  } else if (diffDays <= 7) {
    return {
      text: `${diffDays} days left`,
      badgeClass: 'badge-danger',
      days: diffDays,
      status: 'warning',
    };
  } else if (diffDays <= 30) {
    return {
      text: `${diffDays} days left`,
      badgeClass: 'badge-warning',
      days: diffDays,
      status: 'warning',
    };
  } else {
    return {
      text: `${diffDays} days left`,
      badgeClass: 'badge-success',
      days: diffDays,
      status: 'valid',
    };
  }
}

function setupHistoryModal() {
  const searchInput = document.getElementById('history-search-input');
  const filterChips = document.querySelectorAll('.history-filter-chips .filter-chip');

  elements.btnOpenHistory.addEventListener('click', async () => {
    try {
      const history = await invoke('get_history');
      state.historyItems = history;
      state.historyFilter = 'all';
      state.historySearch = '';
      if (searchInput) searchInput.value = '';

      filterChips.forEach((chip) => {
        chip.classList.toggle('active', chip.getAttribute('data-filter') === 'all');
      });

      filterAndRenderHistory();
      elements.modalHistory.style.display = 'flex';
    } catch (e) {
      showToast(`Failed to load certificates: ${e}`, 'danger');
    }
  });

  elements.btnCloseHistory.addEventListener('click', () => {
    elements.modalHistory.style.display = 'none';
  });

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.historySearch = e.target.value.trim().toLowerCase();
      filterAndRenderHistory();
    });
  }

  filterChips.forEach((chip) => {
    chip.addEventListener('click', () => {
      filterChips.forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      state.historyFilter = chip.getAttribute('data-filter') || 'all';
      filterAndRenderHistory();
    });
  });
}

function filterAndRenderHistory() {
  const items = state.historyItems || [];
  const query = state.historySearch || '';
  const filter = state.historyFilter || 'all';

  const filtered = items.filter((item) => {
    const rem = getRemainingDaysInfo(item.expires_at);

    // Search query match
    if (query) {
      const matchDomain = (item.domain || '').toLowerCase().includes(query);
      const matchSans = (item.sans || '').toLowerCase().includes(query);
      const matchProfile = (item.profile_name || '').toLowerCase().includes(query);
      const matchCa = (item.ca_used || '').toLowerCase().includes(query);
      if (!matchDomain && !matchSans && !matchProfile && !matchCa) {
        return false;
      }
    }

    // Filter chip match
    if (filter === 'valid') {
      return rem.status === 'valid';
    } else if (filter === 'warning') {
      return rem.status === 'warning';
    } else if (filter === 'expired') {
      return rem.status === 'expired';
    }

    return true;
  });

  // Update counter badge
  const countBadge = document.getElementById('history-count-badge');
  if (countBadge) {
    countBadge.textContent = `${filtered.length} of ${items.length} Active`;
  }

  renderHistoryTable(filtered);
}

function renderHistoryTable(items) {
  elements.historyTableBody.innerHTML = '';
  if (items.length === 0) {
    elements.historyTableBody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center text-muted" style="padding: 32px 14px;">
          <div style="font-size: 24px; margin-bottom: 6px;">🔍</div>
          <div>No certificates matching your filter.</div>
        </td>
      </tr>
    `;
    return;
  }

  items.forEach((item) => {
    const rem = getRemainingDaysInfo(item.expires_at);

    // Issue & Expiration Dates
    const issueDateStr = item.issued_at ? item.issued_at.replace('T', ' ').substring(0, 10) : '—';
    let expDateStr = '—';
    if (item.expires_at) {
      try {
        const parsedExp = new Date(item.expires_at);
        if (!isNaN(parsedExp.getTime())) {
          expDateStr = parsedExp.toISOString().substring(0, 10);
        }
      } catch {
        expDateStr = '—';
      }
    }

    // Profile badge
    const profileBadge = item.profile_name
      ? `<span class="badge badge-accent" title="Profile: ${escapeHtml(item.profile_name)}">👤 ${escapeHtml(item.profile_name)}</span>`
      : '<span class="text-muted" style="font-size: 11px;">—</span>';

    // SANs subtext
    const sansDisplay = item.sans && item.sans !== item.domain
      ? `<span class="domain-sans-text" title="${escapeHtml(item.sans)}">SANs: ${escapeHtml(item.sans)}</span>`
      : '';

    // Row 1: Summary & Actions
    const trMain = document.createElement('tr');
    trMain.className = 'history-item-row';
    trMain.innerHTML = `
      <td>
        <div class="font-bold font-mono" style="color: var(--text-primary); font-size: 13px;">${escapeHtml(item.domain)}</div>
        ${sansDisplay}
      </td>
      <td>${profileBadge}</td>
      <td style="font-size: 12px; color: var(--text-secondary);">${issueDateStr}</td>
      <td style="font-size: 12px; font-weight: 500;">${expDateStr}</td>
      <td><span class="badge ${rem.badgeClass}">${rem.text}</span></td>
      <td>
        <div style="font-size: 12px; font-weight: 500;">${escapeHtml(item.ca_used)}</div>
        <span class="badge ${item.is_staging ? 'badge-accent' : 'badge-primary'}" style="font-size: 10px; padding: 1px 6px;">${item.is_staging ? 'Staging' : 'Production'}</span>
      </td>
      <td style="text-align: right; padding-right: 28px;">
        <div style="display: inline-flex; gap: 6px; align-items: center; justify-content: flex-end;">
          <button class="btn btn-primary btn-sm btn-renew-history" data-profile="${escapeHtml(item.profile_name || '')}" data-domain="${escapeHtml(item.domain)}" title="Auto-Renew Certificate using saved profile">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="23 4 23 10 17 10"/>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
            </svg>
            Renew
          </button>
          <button class="btn btn-secondary btn-sm btn-open-history-folder" data-path="${escapeHtml(item.certificate_path)}" title="Open folder in File Manager">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
            </svg>
            Open
          </button>
          <button class="btn btn-ghost btn-sm btn-delete-history text-danger" data-id="${item.id}" data-domain="${escapeHtml(item.domain)}" title="Delete record & certificate folder">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
            </svg>
          </button>
        </div>
      </td>
    `;
    elements.historyTableBody.appendChild(trMain);

    // Row 2: Full Directory Path
    const trPath = document.createElement('tr');
    trPath.className = 'history-path-row';
    trPath.innerHTML = `
      <td colspan="7">
        <div class="history-path-box">
          <div style="display: flex; align-items: center; gap: 6px; overflow: hidden;">
            <span style="font-size: 11px; color: var(--text-muted); font-weight: 500;">📁 Path:</span>
            <span class="history-path-text">${escapeHtml(item.certificate_path)}</span>
          </div>
          <button class="btn btn-ghost btn-sm btn-copy-history-path" data-path="${escapeHtml(item.certificate_path)}" title="Copy Full Directory Path">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
            Copy Path
          </button>
        </div>
      </td>
    `;
    elements.historyTableBody.appendChild(trPath);
  });

  // Renew Certificate Buttons (Zero-Touch Profile-Driven Auto-Renewal)
  elements.historyTableBody.querySelectorAll('.btn-renew-history').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const profileName = btn.getAttribute('data-profile');
      const domain = btn.getAttribute('data-domain');

      if (!profileName) {
        showToast(`No saved profile found for "${domain}". Please configure and save a profile before renewing.`, 'warn');
        return;
      }

      await loadProfiles();
      const profile = (state.profiles || []).find((p) => p.profile_name === profileName);
      if (!profile) {
        showToast(`Saved profile "${profileName}" was not found. Please configure a profile for "${domain}".`, 'warn');
        return;
      }

      // Close Active Domains Modal
      elements.modalHistory.style.display = 'none';

      // Apply Profile into form
      applyProfile(profile);
      elements.profileSelect.value = profile.profile_name;
      elements.btnDeleteProfile.style.display = 'inline-flex';

      showToast(`Starting automated renewal for "${domain}" (Profile: ${profile.profile_name})...`, 'info');
      appendLog('INFO', `[Auto-Renew] Initiating zero-touch automated certificate renewal for domain '${domain}' with profile '${profile.profile_name}'...`);

      // Execute Order & Autopilot directly
      await handleStartOrder();
    });
  });


  // Open Folder Buttons
  elements.historyTableBody.querySelectorAll('.btn-open-history-folder').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const p = btn.getAttribute('data-path');
      showToast(`Opening directory: ${p}`, 'info');
      try {
        await invoke('open_folder', { path: p });
      } catch (e) {
        console.error('Failed to open folder:', e);
        showToast(`Could not open directory: ${e}`, 'danger');
      }
    });
  });

  // Copy Path Buttons
  elements.historyTableBody.querySelectorAll('.btn-copy-history-path').forEach((btn) => {
    btn.addEventListener('click', () => {
      const p = btn.getAttribute('data-path');
      copyToClipboard(p, btn);
    });
  });

  // Delete History Record and Folder
  elements.historyTableBody.querySelectorAll('.btn-delete-history').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = parseInt(btn.getAttribute('data-id'), 10);
      const domain = btn.getAttribute('data-domain');

      if (confirm(`Are you sure you want to delete certificate history for "${domain}" and permanently remove its files from disk?`)) {
        try {
          await invoke('delete_history_item', { id, deleteFiles: true });
          showToast(`Deleted certificate and disk folder for ${domain}`, 'info');
          const refreshed = await invoke('get_history');
          state.historyItems = refreshed;
          filterAndRenderHistory();
        } catch (e) {
          showToast(`Delete failed: ${e}`, 'danger');
        }
      }
    });
  });

}





// ============================================================================
// Live Terminal Logs & Tauri Events
// ============================================================================

function setupLogListener() {
  listen('cert-log', (event) => {
    const payload = event.payload;
    appendLog(payload.level, payload.message, payload.timestamp);
  });
}

let isAutoScrollEnabled = true;

function appendLog(level, message, timeStr = null) {
  const line = document.createElement('div');
  const now = timeStr || new Date().toLocaleTimeString();
  const lvlClass = `log-${level.toLowerCase()}`;

  line.className = `log-line ${lvlClass}`;
  line.innerHTML = `<span class="log-time">[${now}]</span> <span class="log-msg">${escapeHtml(message)}</span>`;

  elements.terminalBody.appendChild(line);

  // Trim excess log lines to prevent memory bloat (keep latest 500 lines)
  while (elements.terminalBody.childElementCount > 500) {
    elements.terminalBody.removeChild(elements.terminalBody.firstElementChild);
  }

  if (isAutoScrollEnabled) {
    line.scrollIntoView({ behavior: 'auto', block: 'end' });
    elements.terminalBody.scrollTop = elements.terminalBody.scrollHeight;
  }
}


function setupTerminalActions() {
  const btnToggleAutoScroll = document.getElementById('btn-toggle-autoscroll');
  const btnScrollBottom = document.getElementById('btn-scroll-bottom');

  if (btnToggleAutoScroll) {
    btnToggleAutoScroll.addEventListener('click', () => {
      isAutoScrollEnabled = !isAutoScrollEnabled;
      btnToggleAutoScroll.classList.toggle('active', isAutoScrollEnabled);
      if (isAutoScrollEnabled) {
        elements.terminalBody.scrollTop = elements.terminalBody.scrollHeight + 100;
        if (btnScrollBottom) btnScrollBottom.style.display = 'none';
        showToast('Terminal Auto-Scroll: ON', 'info');
      } else {
        showToast('Terminal Auto-Scroll: PAUSED', 'info');
      }
    });
  }

  // Detect user scroll position
  elements.terminalBody.addEventListener('scroll', () => {
    const threshold = 40;
    const isAtBottom = elements.terminalBody.scrollHeight - elements.terminalBody.scrollTop - elements.terminalBody.clientHeight < threshold;
    if (btnScrollBottom) {
      btnScrollBottom.style.display = isAtBottom ? 'none' : 'inline-flex';
    }
  });

  if (btnScrollBottom) {
    btnScrollBottom.addEventListener('click', () => {
      elements.terminalBody.scrollTop = elements.terminalBody.scrollHeight + 100;
      isAutoScrollEnabled = true;
      if (btnToggleAutoScroll) btnToggleAutoScroll.classList.add('active');
      btnScrollBottom.style.display = 'none';
    });
  }


  elements.btnCopyLogs.addEventListener('click', () => {
    const text = elements.terminalBody.innerText;
    copyToClipboard(text);
    showToast('Logs copied to clipboard', 'info');
  });

  elements.btnClearLogs.addEventListener('click', () => {
    elements.terminalBody.innerHTML = `
      <div class="log-line log-system">
        <span class="log-time">[System]</span>
        <span class="log-msg">Logs cleared.</span>
      </div>
    `;
    if (btnScrollBottom) btnScrollBottom.style.display = 'none';
  });

  // Restore saved terminal height
  const savedTerminalHeight = localStorage.getItem('acmerc_terminal_height');
  const rightPanel = document.querySelector('.right-panel');
  if (savedTerminalHeight && rightPanel) {
    const parsedH = parseInt(savedTerminalHeight, 10);
    if (parsedH >= 60 && parsedH <= window.innerHeight * 0.8) {
      rightPanel.style.height = `${parsedH}px`;
    }
  }

  // Interactive Resizer Dragging
  const resizer = document.getElementById('terminal-resizer');
  const iconToggle = document.getElementById('icon-terminal-toggle');
  const btnToggleTerminal = document.getElementById('btn-toggle-terminal');

  if (resizer && rightPanel) {
    let isDragging = false;
    let startY = 0;
    let startHeight = 0;

    const onMouseDown = (e) => {
      if (rightPanel.classList.contains('collapsed')) {
        rightPanel.classList.remove('collapsed');
        if (iconToggle) {
          iconToggle.innerHTML = '<polyline points="6 9 12 15 18 9"/>';
        }
      }
      isDragging = true;
      startY = e.clientY;
      startHeight = rightPanel.getBoundingClientRect().height;
      document.body.classList.add('is-resizing');
      resizer.classList.add('active');
      rightPanel.classList.remove('animating');

      window.addEventListener('mousemove', onMouseMove);
      window.addEventListener('mouseup', onMouseUp);
    };

    const onMouseMove = (e) => {
      if (!isDragging) return;
      const deltaY = startY - e.clientY;
      const minH = 70;
      const maxH = Math.floor(window.innerHeight * 0.75);
      const newH = Math.max(minH, Math.min(maxH, startHeight + deltaY));
      rightPanel.style.height = `${newH}px`;
    };

    const onMouseUp = () => {
      if (!isDragging) return;
      isDragging = false;
      document.body.classList.remove('is-resizing');
      resizer.classList.remove('active');
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);

      const finalH = parseInt(rightPanel.style.height, 10);
      if (finalH) {
        localStorage.setItem('acmerc_terminal_height', finalH.toString());
      }
    };

    resizer.addEventListener('mousedown', onMouseDown);
  }

  // Minimize / Expand Terminal Drawer Toggle with smooth animation
  if (btnToggleTerminal && rightPanel) {
    btnToggleTerminal.addEventListener('click', () => {
      rightPanel.classList.add('animating');
      const isCollapsed = rightPanel.classList.toggle('collapsed');
      btnToggleTerminal.title = isCollapsed ? 'Expand Terminal' : 'Minimize Terminal';
      if (iconToggle) {
        iconToggle.innerHTML = isCollapsed
          ? '<polyline points="18 15 12 9 6 15"/>'
          : '<polyline points="6 9 12 15 18 9"/>';
      }
      setTimeout(() => rightPanel.classList.remove('animating'), 300);
    });
  }
}


// ============================================================================
// Utilities: Toast, Clipboard & Helpers
// ============================================================================

function copyToClipboard(text, btnElement = null) {
  navigator.clipboard.writeText(text).then(() => {
    if (btnElement) {
      btnElement.classList.add('copied');
      setTimeout(() => btnElement.classList.remove('copied'), 1500);
    }
    showToast('Copied to clipboard!', 'success');
  }).catch(() => {
    showToast('Clipboard access failed', 'danger');
  });
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;

  elements.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

function setButtonLoading(btn, isLoading, label) {
  if (isLoading) {
    btn.disabled = true;
    if (!btn.dataset.originalText) {
      btn.dataset.originalText = btn.innerHTML;
    }
    btn.innerHTML = `<span class="icon-spin">⟳</span> ${label}`;
  } else {
    btn.disabled = false;
    btn.innerHTML = btn.dataset.originalText || label;
  }
}


function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Prevent window-level scrolling when inputs are focused in small windows
window.addEventListener('scroll', () => {
  if (window.scrollY !== 0 || window.scrollX !== 0) {
    window.scrollTo(0, 0);
  }
});

// Initialize on DOM Ready
window.addEventListener('DOMContentLoaded', initApp);
