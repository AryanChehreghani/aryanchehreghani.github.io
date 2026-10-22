/**
 * Anti-Stealer Enterprise Audit Platform
 * Multi-Stage Assessment Engine (Phase 1, 2, 3 & 4 Complete)
 */

const STORAGE_KEY = 'anti_stealer_enterprise_audit_v4';

// Application State
let auditState = {
    activeStep: 1, // 1 | 2 | 3 | 4
    
    // Step 1: Threat Vectors Awareness (19 Vectors)
    step1Completed: false,
    step1Score: 0,
    step1Assessments: {}, // [vectorId]: { familiarity: 0 | 35 | 70 | 100, isExposed: boolean }
    
    // Step 2: Asset Hardening & Configuration (29 Items)
    step2Completed: false,
    step2Score: 0,
    step2Answers: {}, // [itemId]: optionValue (0 | 40 | 50 | 100)
    
    // Step 3: Incident Response & Containment Readiness (16 Items)
    step3Completed: false,
    step3Score: 0,
    step3Answers: {}, // [itemId]: optionValue (0 | 30 | 40 | 50 | 100)
    
    // Step 4: Overall Certificate & Remediation
    overallScore: 0,
    auditDate: null,
    
    // UI Filters and Search
    currentCategoryStep1: 'all',
    searchQueryStep1: '',
    currentCategoryStep2: 'all',
    searchQueryStep2: '',
    currentCategoryStep3: 'all',
    searchQueryStep3: ''
};

// Familiarity segmented options for Step 1
const FAMILIARITY_LEVELS = [
    { value: 0, label: 'عدم آشنایی', sub: 'ناآگاه' },
    { value: 35, label: 'آشنایی سطحی', sub: 'فقط نام' },
    { value: 70, label: 'آشنایی کاربردی', sub: 'شناخت ترفند' },
    { value: 100, label: 'تسلط کامل', sub: 'شناخت و ایمن‌سازی' }
];

function loadState() {
    try {
        const saved = localStorage.getItem(STORAGE_KEY) || 
                      localStorage.getItem('anti_stealer_enterprise_audit_v3') || 
                      localStorage.getItem('anti_stealer_enterprise_audit_v2');
        if (saved) {
            const parsed = JSON.parse(saved);
            auditState = Object.assign(auditState, parsed);
            // Backward compatibility
            if (parsed.assessments && Object.keys(parsed.assessments).length > 0 && !auditState.step1Assessments) {
                auditState.step1Assessments = parsed.assessments;
            }
            if (!auditState.step2Answers) auditState.step2Answers = {};
            if (!auditState.step3Answers) auditState.step3Answers = {};
        }
    } catch (e) {
        console.warn('Could not load state:', e);
    }

    // Always reset categories and search to show ALL items by default on page load
    auditState.currentCategoryStep1 = 'all';
    auditState.searchQueryStep1 = '';
    auditState.currentCategoryStep2 = 'all';
    auditState.searchQueryStep2 = '';
    auditState.currentCategoryStep3 = 'all';
    auditState.searchQueryStep3 = '';
}

function persistState() {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(auditState));
    } catch (e) {
        console.warn('Could not save state:', e);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadState();
    
    // Clear search inputs
    const s1Search = document.getElementById('searchInput');
    if (s1Search) s1Search.value = '';
    const s2Search = document.getElementById('step2SearchInput');
    if (s2Search) s2Search.value = '';
    const s3Search = document.getElementById('step3SearchInput');
    if (s3Search) s3Search.value = '';

    // Initialize Step 1
    initStep1Filters();
    initStep1EventListeners();
    renderStep1View();
    updateStep1Progress();

    // Initialize Step 2
    initStep2Filters();
    initStep2EventListeners();
    renderStep2View();
    updateStep2Progress();

    // Initialize Step 3
    initStep3Filters();
    initStep3EventListeners();
    renderStep3View();
    updateStep3Progress();

    // Initialize Step 4
    initStep4EventListeners();

    // Stepper header click listeners
    initStepperNavigation();

    // Initial view switch based on saved state
    if (auditState.activeStep === 4 && auditState.step3Completed) {
        switchToStep(4);
    } else if (auditState.activeStep === 3 && auditState.step2Completed) {
        switchToStep(3);
    } else if (auditState.activeStep === 2 && auditState.step1Completed) {
        switchToStep(2);
    } else {
        switchToStep(1);
    }
});

// Stepper click handlers
function initStepperNavigation() {
    const s1 = document.getElementById('stepNavItem-1');
    if (s1) {
        s1.addEventListener('click', () => {
            switchToStep(1);
        });
    }

    const s2 = document.getElementById('stepNavItem-2');
    if (s2) {
        s2.addEventListener('click', () => {
            if (auditState.step1Completed) {
                switchToStep(2);
            } else {
                showToast('لطفاً ابتدا مرحله ۱ را تکمیل و ثبت نمایید.');
            }
        });
    }

    const s3 = document.getElementById('stepNavItem-3');
    if (s3) {
        s3.addEventListener('click', () => {
            if (auditState.step1Completed && auditState.step2Completed) {
                switchToStep(3);
            } else {
                showToast('مراحل ۱ و ۲ باید قبل از این بخش تکمیل شوند.');
            }
        });
    }

    const s4 = document.getElementById('stepNavItem-4');
    if (s4) {
        s4.addEventListener('click', () => {
            if (auditState.step1Completed && auditState.step2Completed && auditState.step3Completed) {
                switchToStep(4);
            } else {
                showToast('برای مشاهده کارنامه نهایی، باید مراحل ۱، ۲ و ۳ را کامل کنید.');
            }
        });
    }
}

// -------------------------------------------------------------
// STEP 1 LOGIC (Threat Vectors Awareness)
// -------------------------------------------------------------

function initStep1Filters() {
    const filtersContainer = document.getElementById('categoryFilters');
    if (!filtersContainer) return;
    filtersContainer.innerHTML = '';

    const allBtn = document.createElement('button');
    allBtn.className = 'filter-btn active';
    allBtn.id = 'filter-all';
    allBtn.textContent = `همه موارد (${STEALER_VECTORS.length})`;
    allBtn.addEventListener('click', () => setStep1Category('all'));
    filtersContainer.appendChild(allBtn);

    Object.keys(VECTOR_CATEGORIES).forEach(key => {
        const cat = VECTOR_CATEGORIES[key];
        const count = STEALER_VECTORS.filter(v => v.category === cat.id).length;
        const btn = document.createElement('button');
        btn.className = 'filter-btn';
        btn.id = `filter-${cat.id}`;
        btn.textContent = `${cat.label} (${count})`;
        btn.addEventListener('click', () => setStep1Category(cat.id));
        filtersContainer.appendChild(btn);
    });
}

function initStep1EventListeners() {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            auditState.searchQueryStep1 = e.target.value.trim().toLowerCase();
            renderStep1View();
        });
    }

    const resetBtn = document.getElementById('resetStep1Btn');
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            if (confirm('آیا از بازنشانی کلیه پاسخ‌های مرحله ۱ اطمینان دارید؟')) {
                auditState.step1Assessments = {};
                auditState.step1Completed = false;
                auditState.step1Score = 0;
                auditState.activeStep = 1;
                persistState();
                renderStep1View();
                updateStep1Progress();
                updateStepperUI();
                switchToStep(1);
                showToast('اطلاعات مرحله ۱ بازنشانی شد');
            }
        });
    }

    const completeStep1Btn = document.getElementById('completeStep1Btn');
    if (completeStep1Btn) {
        completeStep1Btn.addEventListener('click', completeStep1);
    }

    const backToStep1Btn = document.getElementById('backToStep1Btn');
    if (backToStep1Btn) {
        backToStep1Btn.addEventListener('click', () => switchToStep(1));
    }

    // Modal
    const closeBtn = document.getElementById('closeTechModalBtn');
    if (closeBtn) closeBtn.addEventListener('click', closeTechModal);
    const techModal = document.getElementById('techModal');
    if (techModal) {
        techModal.addEventListener('click', (e) => {
            if (e.target.id === 'techModal') closeTechModal();
        });
    }
}

function setStep1Category(catId) {
    auditState.currentCategoryStep1 = catId;
    document.querySelectorAll('#categoryFilters .filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.id === `filter-${catId}`);
    });
    renderStep1View();
}

function renderStep1View() {
    const list = document.getElementById('vectorList');
    if (!list) return;
    list.innerHTML = '';

    const filtered = STEALER_VECTORS.filter(vector => {
        const matchesCat = auditState.currentCategoryStep1 === 'all' || vector.category === auditState.currentCategoryStep1;
        const matchesQuery = !auditState.searchQueryStep1 ||
            vector.title.toLowerCase().includes(auditState.searchQueryStep1) ||
            vector.subtitle.toLowerCase().includes(auditState.searchQueryStep1) ||
            vector.summary.toLowerCase().includes(auditState.searchQueryStep1);
        return matchesCat && matchesQuery;
    });

    const metaElem = document.getElementById('step1DisplayMeta');
    if (metaElem) {
        metaElem.textContent = `نمایش ${filtered.length} از ${STEALER_VECTORS.length} بردار نفوذ`;
    }

    if (filtered.length === 0) {
        list.innerHTML = `
            <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 36px; text-align: center; color: var(--text-muted);">
                موردی مطابق با جستجوی شما یافت نشد.
            </div>
        `;
        return;
    }

    filtered.forEach((vector) => {
        const userAssessment = (auditState.step1Assessments && auditState.step1Assessments[vector.id]) || { familiarity: null, isExposed: false };
        const catMeta = VECTOR_CATEGORIES[vector.category] || { label: 'عمومی' };

        const item = document.createElement('div');
        item.className = 'vector-item';
        item.id = `item-${vector.id}`;

        const main = document.createElement('div');
        main.className = 'vector-main';

        const realIndex = STEALER_VECTORS.findIndex(v => v.id === vector.id) + 1;
        const indexStr = realIndex < 10 ? `0${realIndex}` : `${realIndex}`;

        main.innerHTML = `
            <div class="vector-header-meta">
                <span class="vector-index">#${indexStr}</span>
                <span class="vector-category-tag">${catMeta.label}</span>
                <span class="vector-severity-tag severity-${vector.severity}">
                    ${vector.severity === 'critical' ? 'اولویت بحرانی' : 'اولویت بالا'}
                </span>
                <span style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono); margin-right: auto;">
                    ${vector.prevalence}
                </span>
            </div>

            <div class="vector-title-row">
                <h3 class="vector-title">${vector.title}</h3>
                <span class="vector-subtitle">${vector.subtitle}</span>
            </div>

            <p class="vector-desc">${vector.summary}</p>

            <div class="vector-footer-links">
                <button class="link-btn" id="tech-btn-${vector.id}">
                    <span>مشاهده تحلیل فنی و راهنمای پیشگیری</span>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                </button>
                <span class="malware-intel-note">
                    نمونه بدافزارها: ${vector.realWorldMalware.slice(0, 3).join(', ')}
                </span>
            </div>
        `;

        main.querySelector(`#tech-btn-${vector.id}`).addEventListener('click', () => {
            openStep1TechModal(vector);
        });

        const inputs = document.createElement('div');
        inputs.className = 'vector-inputs';

        let statusText = 'نامشخص';
        if (userAssessment.familiarity !== null) {
            const found = FAMILIARITY_LEVELS.find(l => l.value === userAssessment.familiarity);
            if (found) statusText = found.label;
        }

        inputs.innerHTML = `
            <div class="selector-label">
                <span>سطح شناخت شما:</span>
                <span class="selector-status" id="status-label-${vector.id}">${statusText}</span>
            </div>
            <div class="segmented-group" id="seg-${vector.id}"></div>
            <label class="exposure-checkbox-row">
                <input type="checkbox" class="exposure-input" id="expose-${vector.id}" ${userAssessment.isExposed ? 'checked' : ''}>
                <span>سابقه فعالیت یا مواجهه در این محیط</span>
            </label>
        `;

        const segGroup = inputs.querySelector(`#seg-${vector.id}`);
        FAMILIARITY_LEVELS.forEach(lvl => {
            const btn = document.createElement('button');
            btn.type = 'button';
            const isActive = userAssessment.familiarity === lvl.value;
            btn.className = `segment-btn ${isActive ? `active-${lvl.value}` : ''}`;
            btn.textContent = lvl.label;
            btn.addEventListener('click', () => setVectorFamiliarity(vector.id, lvl.value));
            segGroup.appendChild(btn);
        });

        const exposeCheckbox = inputs.querySelector(`#expose-${vector.id}`);
        exposeCheckbox.addEventListener('change', (e) => {
            setVectorExposure(vector.id, e.target.checked);
        });

        item.appendChild(main);
        item.appendChild(inputs);
        list.appendChild(item);
    });
}

function setVectorFamiliarity(vectorId, val) {
    if (!auditState.step1Assessments) auditState.step1Assessments = {};
    if (!auditState.step1Assessments[vectorId]) {
        auditState.step1Assessments[vectorId] = { familiarity: null, isExposed: false };
    }
    auditState.step1Assessments[vectorId].familiarity = val;
    persistState();
    
    // In-place DOM update without destroying list
    const segGroup = document.getElementById(`seg-${vectorId}`);
    if (segGroup) {
        segGroup.querySelectorAll('.segment-btn').forEach((btn, idx) => {
            const lvl = FAMILIARITY_LEVELS[idx];
            if (lvl) {
                btn.className = `segment-btn ${lvl.value === val ? `active-${lvl.value}` : ''}`;
            }
        });
    }
    const statusLabel = document.getElementById(`status-label-${vectorId}`);
    if (statusLabel) {
        const found = FAMILIARITY_LEVELS.find(l => l.value === val);
        if (found) statusLabel.textContent = found.label;
    }

    updateStep1Progress();
}

function setVectorExposure(vectorId, isExposed) {
    if (!auditState.step1Assessments) auditState.step1Assessments = {};
    if (!auditState.step1Assessments[vectorId]) {
        auditState.step1Assessments[vectorId] = { familiarity: null, isExposed: false };
    }
    auditState.step1Assessments[vectorId].isExposed = isExposed;
    persistState();
    updateStep1Progress();
}

function calculateStep1() {
    const total = STEALER_VECTORS.length;
    let assessedCount = 0;
    let totalScore = 0;

    STEALER_VECTORS.forEach(v => {
        const item = auditState.step1Assessments && auditState.step1Assessments[v.id];
        if (item && item.familiarity !== null) {
            assessedCount++;
            totalScore += item.familiarity;
        }
    });

    const score = assessedCount > 0 ? Math.round(totalScore / total) : 0;
    const isComplete = assessedCount === total;
    return { total, assessedCount, score, isComplete };
}

function updateStep1Progress() {
    const calc = calculateStep1();
    auditState.step1Score = calc.score;

    const countElem = document.getElementById('assessedCount');
    if (countElem) countElem.textContent = calc.assessedCount;
    const totalElem = document.getElementById('totalVectorsCount');
    if (totalElem) totalElem.textContent = calc.total;

    const percent = Math.round((calc.assessedCount / calc.total) * 100);
    const bar = document.getElementById('step1ProgressBar');
    if (bar) bar.style.width = `${percent}%`;
    const label = document.getElementById('progressPercentageLabel');
    if (label) label.textContent = `${percent}% تکمیل شده`;

    const scoreFooter = document.getElementById('footerStep1Score');
    if (scoreFooter) scoreFooter.textContent = calc.score;

    const completeBtn = document.getElementById('completeStep1Btn');
    const footerTitle = document.getElementById('footerStatusTitle');
    const footerDesc = document.getElementById('footerStatusDesc');

    if (completeBtn && footerTitle && footerDesc) {
        if (calc.isComplete) {
            completeBtn.disabled = false;
            footerTitle.textContent = 'کلیه ۱۹ بردار مرحله ۱ ارزیابی گردید';
            footerDesc.textContent = `امتیاز شناخت مرحله ۱: ${calc.score} از ۱۰۰. اکنون آماده ثبت و ورود به مرحله دوم هستید.`;
        } else {
            completeBtn.disabled = true;
            const remaining = calc.total - calc.assessedCount;
            footerTitle.textContent = `در حال ارزیابی (${calc.assessedCount} از ${calc.total} بردار)`;
            footerDesc.textContent = `هنوز ${remaining} بردار باقیمانده است. برای تایید مرحله، تمام گزینه‌ها را مشخص نمایید.`;
        }
    }

    updateStepperUI();
}

function completeStep1() {
    const calc = calculateStep1();
    if (!calc.isComplete) {
        alert('لطفاً ابتدا تمام ۱۹ بردار مرحله ۱ را مشخص فرمایید.');
        return;
    }

    auditState.step1Completed = true;
    auditState.step1Score = calc.score;
    auditState.activeStep = 2;
    persistState();

    switchToStep(2);
    showToast(`مرحله ۱ با امتیاز ${calc.score} از ۱۰۰ ثبت شد`);
}

// -------------------------------------------------------------
// STEP 2 LOGIC (Asset Hardening & System Exposure Audit)
// -------------------------------------------------------------

function initStep2Filters() {
    const filtersContainer = document.getElementById('step2CategoryFilters');
    if (!filtersContainer) return;
    filtersContainer.innerHTML = '';

    const allBtn = document.createElement('button');
    allBtn.className = 'filter-btn active';
    allBtn.id = 'filter-s2-all';
    allBtn.textContent = `همه موارد (${STEP2_ITEMS.length})`;
    allBtn.addEventListener('click', () => setStep2Category('all'));
    filtersContainer.appendChild(allBtn);

    Object.keys(STEP2_CATEGORIES).forEach(key => {
        const cat = STEP2_CATEGORIES[key];
        const count = STEP2_ITEMS.filter(item => item.category === cat.id).length;
        const btn = document.createElement('button');
        btn.className = 'filter-btn';
        btn.id = `filter-s2-${cat.id}`;
        btn.textContent = `${cat.label} (${count})`;
        btn.addEventListener('click', () => setStep2Category(cat.id));
        filtersContainer.appendChild(btn);
    });
}

function initStep2EventListeners() {
    const searchInput = document.getElementById('step2SearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            auditState.searchQueryStep2 = e.target.value.trim().toLowerCase();
            renderStep2View();
        });
    }

    const completeStep2Btn = document.getElementById('completeStep2Btn');
    if (completeStep2Btn) {
        completeStep2Btn.addEventListener('click', completeStep2);
    }

    const backToStep2Btn = document.getElementById('backToStep2Btn');
    if (backToStep2Btn) {
        backToStep2Btn.addEventListener('click', () => switchToStep(2));
    }
}

function setStep2Category(catId) {
    auditState.currentCategoryStep2 = catId;
    document.querySelectorAll('#step2CategoryFilters .filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.id === `filter-s2-${catId}`);
    });
    renderStep2View();
}

function renderStep2View() {
    const list = document.getElementById('step2List');
    if (!list) return;
    list.innerHTML = '';

    const filtered = STEP2_ITEMS.filter(item => {
        const matchesCat = auditState.currentCategoryStep2 === 'all' || item.category === auditState.currentCategoryStep2;
        const matchesQuery = !auditState.searchQueryStep2 ||
            item.title.toLowerCase().includes(auditState.searchQueryStep2) ||
            item.subtitle.toLowerCase().includes(auditState.searchQueryStep2) ||
            item.question.toLowerCase().includes(auditState.searchQueryStep2);
        return matchesCat && matchesQuery;
    });

    const metaElem = document.getElementById('step2DisplayMeta');
    if (metaElem) {
        metaElem.textContent = `نمایش ${filtered.length} از ${STEP2_ITEMS.length} مؤلفه استحکام`;
    }

    if (filtered.length === 0) {
        list.innerHTML = `
            <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 36px; text-align: center; color: var(--text-muted);">
                موردی مطابق با جستجوی شما یافت نشد.
            </div>
        `;
        return;
    }

    filtered.forEach((item) => {
        const selectedValue = auditState.step2Answers ? auditState.step2Answers[item.id] : undefined;
        const catMeta = STEP2_CATEGORIES[item.category] || { label: 'عمومی' };

        const card = document.createElement('div');
        card.className = 'vector-item';
        card.id = `s2-item-${item.id}`;

        const main = document.createElement('div');
        main.className = 'vector-main';

        const realIndex = STEP2_ITEMS.findIndex(i => i.id === item.id) + 1;
        const indexStr = realIndex < 10 ? `0${realIndex}` : `${realIndex}`;

        let severityLabel = 'اولویت بالا';
        if (item.severity === 'critical') severityLabel = 'اولویت بحرانی';
        else if (item.severity === 'medium') severityLabel = 'اولویت متوسط';

        main.innerHTML = `
            <div class="vector-header-meta">
                <span class="vector-index">#${indexStr}</span>
                <span class="vector-category-tag">${catMeta.label}</span>
                <span class="vector-severity-tag severity-${item.severity}">
                    ${severityLabel}
                </span>
                <span style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono); margin-right: auto;">
                    ضریب ریسک: ${item.weight}x
                </span>
            </div>

            <div class="vector-title-row">
                <h3 class="vector-title">${item.title}</h3>
                <span class="vector-subtitle">${item.subtitle}</span>
            </div>

            <p class="vector-desc" style="color: #cbd5e1; font-weight: 500;">${item.question}</p>
            <p class="vector-desc" style="font-size: 0.77rem; color: var(--text-muted);">${item.technicalImpact}</p>

            <div class="vector-footer-links">
                <button class="link-btn" id="s2-tech-btn-${item.id}">
                    <span>مشاهده راهکار اصلاحی و تحلیل اثرگذاری</span>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                </button>
            </div>
        `;

        main.querySelector(`#s2-tech-btn-${item.id}`).addEventListener('click', () => {
            openStep2TechModal(item);
        });

        // Right side: Segmented Options (3 compliance states)
        const inputs = document.createElement('div');
        inputs.className = 'vector-inputs';

        let currentOptionLabel = 'مشخص نشده';
        if (selectedValue !== undefined) {
            const foundOpt = item.options.find(o => o.value === selectedValue);
            if (foundOpt) currentOptionLabel = foundOpt.label;
        }

        inputs.innerHTML = `
            <div class="selector-label">
                <span>وضعیت در سیستم شما:</span>
                <span class="selector-status" id="s2-status-${item.id}">${currentOptionLabel}</span>
            </div>
            <div class="step2-segmented-group" id="s2-seg-${item.id}"></div>
        `;

        const segGroup = inputs.querySelector(`#s2-seg-${item.id}`);
        item.options.forEach(opt => {
            const btn = document.createElement('button');
            btn.type = 'button';
            const isSelected = selectedValue === opt.value;
            btn.className = `segment-btn ${isSelected ? `active-${opt.scoreType}` : ''}`;
            btn.textContent = opt.label;
            btn.title = opt.label;
            btn.addEventListener('click', () => setStep2Answer(item.id, opt.value));
            segGroup.appendChild(btn);
        });

        card.appendChild(main);
        card.appendChild(inputs);
        list.appendChild(card);
    });
}

function setStep2Answer(itemId, optionValue) {
    if (!auditState.step2Answers) auditState.step2Answers = {};
    auditState.step2Answers[itemId] = optionValue;
    persistState();
    
    // In-place DOM update
    const item = STEP2_ITEMS.find(i => i.id === itemId);
    const segGroup = document.getElementById(`s2-seg-${itemId}`);
    if (segGroup && item) {
        segGroup.querySelectorAll('.segment-btn').forEach((btn, idx) => {
            const opt = item.options[idx];
            if (opt) {
                btn.className = `segment-btn ${opt.value === optionValue ? `active-${opt.scoreType}` : ''}`;
            }
        });
    }
    const statusLabel = document.getElementById(`s2-status-${itemId}`);
    if (statusLabel && item) {
        const foundOpt = item.options.find(o => o.value === optionValue);
        if (foundOpt) statusLabel.textContent = foundOpt.label;
    }

    updateStep2Progress();
}

function calculateStep2() {
    const total = STEP2_ITEMS.length;
    let assessedCount = 0;
    let userWeightedScore = 0;
    let maxWeightedScore = 0;

    STEP2_ITEMS.forEach(item => {
        maxWeightedScore += (item.weight * 100);
        const val = auditState.step2Answers ? auditState.step2Answers[item.id] : undefined;
        if (val !== undefined) {
            assessedCount++;
            userWeightedScore += (item.weight * val);
        }
    });

    const score = maxWeightedScore > 0 ? Math.round((userWeightedScore / maxWeightedScore) * 100) : 0;
    const isComplete = assessedCount === total;
    return { total, assessedCount, score, isComplete };
}

function updateStep2Progress() {
    const calc = calculateStep2();
    auditState.step2Score = calc.score;

    const countElem = document.getElementById('step2AssessedCount');
    if (countElem) countElem.textContent = calc.assessedCount;
    const totalElem = document.getElementById('step2TotalCount');
    if (totalElem) totalElem.textContent = calc.total;

    const percent = Math.round((calc.assessedCount / calc.total) * 100);
    const bar = document.getElementById('step2ProgressBar');
    if (bar) bar.style.width = `${percent}%`;
    const label = document.getElementById('step2ProgressLabel');
    if (label) label.textContent = `${percent}% بررسی شده`;

    const scoreFooter = document.getElementById('footerStep2Score');
    if (scoreFooter) scoreFooter.textContent = calc.score;

    const completeBtn = document.getElementById('completeStep2Btn');
    const footerTitle = document.getElementById('footerStep2StatusTitle');
    const footerDesc = document.getElementById('footerStep2StatusDesc');

    if (completeBtn && footerTitle && footerDesc) {
        if (calc.isComplete) {
            completeBtn.disabled = false;
            footerTitle.textContent = 'تمام ۲۹ مؤلفه مرحله ۲ بررسی شد';
            footerDesc.textContent = `امتیاز استحکام مرحله ۲: ${calc.score} از ۱۰۰. اکنون آماده ثبت و انتقال به مرحله بعدی هستید.`;
        } else {
            completeBtn.disabled = true;
            const remaining = calc.total - calc.assessedCount;
            footerTitle.textContent = `در حال بررسی (${calc.assessedCount} از ${calc.total} مؤلفه)`;
            footerDesc.textContent = `هنوز ${remaining} مورد باقیمانده است. برای تایید نهایی تمام موارد را علامت بزنید.`;
        }
    }

    updateStepperUI();
}

function completeStep2() {
    const calc = calculateStep2();
    if (!calc.isComplete) {
        alert('لطفاً ابتدا تمام ۲۹ مؤلفه مرحله ۲ را مشخص فرمایید.');
        return;
    }

    auditState.step2Completed = true;
    auditState.step2Score = calc.score;
    auditState.activeStep = 3;
    persistState();

    switchToStep(3);
    showToast(`مرحله ۲ با امتیاز استحکام ${calc.score} از ۱۰۰ ثبت گردید`);
}

// -------------------------------------------------------------
// STEP 3 LOGIC (Incident Response & Containment Readiness)
// -------------------------------------------------------------

function initStep3Filters() {
    const filtersContainer = document.getElementById('step3CategoryFilters');
    if (!filtersContainer) return;
    filtersContainer.innerHTML = '';

    const allBtn = document.createElement('button');
    allBtn.className = 'filter-btn active';
    allBtn.id = 'filter-s3-all';
    allBtn.textContent = `همه موارد (${STEP3_ITEMS.length})`;
    allBtn.addEventListener('click', () => setStep3Category('all'));
    filtersContainer.appendChild(allBtn);

    Object.keys(STEP3_CATEGORIES).forEach(key => {
        const cat = STEP3_CATEGORIES[key];
        const count = STEP3_ITEMS.filter(item => item.category === cat.id).length;
        const btn = document.createElement('button');
        btn.className = 'filter-btn';
        btn.id = `filter-s3-${cat.id}`;
        btn.textContent = `${cat.label} (${count})`;
        btn.addEventListener('click', () => setStep3Category(cat.id));
        filtersContainer.appendChild(btn);
    });
}

function initStep3EventListeners() {
    const searchInput = document.getElementById('step3SearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            auditState.searchQueryStep3 = e.target.value.trim().toLowerCase();
            renderStep3View();
        });
    }

    const completeStep3Btn = document.getElementById('completeStep3Btn');
    if (completeStep3Btn) {
        completeStep3Btn.addEventListener('click', completeStep3);
    }

    const backToStep2Btn = document.getElementById('backToStep2Btn');
    if (backToStep2Btn) {
        backToStep2Btn.addEventListener('click', () => switchToStep(2));
    }
}

function setStep3Category(catId) {
    auditState.currentCategoryStep3 = catId;
    document.querySelectorAll('#step3CategoryFilters .filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.id === `filter-s3-${catId}`);
    });
    renderStep3View();
}

function renderStep3View() {
    const list = document.getElementById('step3List');
    if (!list) return;
    list.innerHTML = '';

    const filtered = STEP3_ITEMS.filter(item => {
        const matchesCat = auditState.currentCategoryStep3 === 'all' || item.category === auditState.currentCategoryStep3;
        const matchesQuery = !auditState.searchQueryStep3 ||
            item.title.toLowerCase().includes(auditState.searchQueryStep3) ||
            item.subtitle.toLowerCase().includes(auditState.searchQueryStep3) ||
            item.question.toLowerCase().includes(auditState.searchQueryStep3);
        return matchesCat && matchesQuery;
    });

    const metaElem = document.getElementById('step3DisplayMeta');
    if (metaElem) {
        metaElem.textContent = `نمایش ${filtered.length} از ${STEP3_ITEMS.length} پروتکل بحران`;
    }

    if (filtered.length === 0) {
        list.innerHTML = `
            <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 36px; text-align: center; color: var(--text-muted);">
                موردی مطابق با جستجوی شما در پروتکل‌های مرحله ۳ یافت نشد.
            </div>
        `;
        return;
    }

    filtered.forEach((item) => {
        const selectedValue = auditState.step3Answers ? auditState.step3Answers[item.id] : undefined;
        const catMeta = STEP3_CATEGORIES[item.category] || { label: 'مهار و واکنش' };

        const card = document.createElement('div');
        card.className = 'vector-item';
        card.id = `s3-item-${item.id}`;

        const main = document.createElement('div');
        main.className = 'vector-main';

        const realIndex = STEP3_ITEMS.findIndex(i => i.id === item.id) + 1;
        const indexStr = realIndex < 10 ? `0${realIndex}` : `${realIndex}`;

        let severityLabel = 'اولویت بالا';
        if (item.severity === 'critical') severityLabel = 'اولویت بحرانی';
        else if (item.severity === 'medium') severityLabel = 'اولویت متوسط';

        main.innerHTML = `
            <div class="vector-header-meta">
                <span class="vector-index">#${indexStr}</span>
                <span class="vector-category-tag">${catMeta.label}</span>
                <span class="vector-severity-tag severity-${item.severity}">
                    ${severityLabel}
                </span>
                <span style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono); margin-right: auto;">
                    ضریب ریسک: ${item.weight}x
                </span>
            </div>

            <div class="vector-title-row">
                <h3 class="vector-title">${item.title}</h3>
                <span class="vector-subtitle">${item.subtitle}</span>
            </div>

            <p class="vector-desc" style="color: #cbd5e1; font-weight: 500;">${item.question}</p>
            <p class="vector-desc" style="font-size: 0.77rem; color: var(--text-muted);">${item.technicalImpact}</p>

            <div class="vector-footer-links">
                <button class="link-btn" id="s3-tech-btn-${item.id}">
                    <span>مشاهده راهکار عملیاتی واکنش سریع</span>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                </button>
            </div>
        `;

        main.querySelector(`#s3-tech-btn-${item.id}`).addEventListener('click', () => {
            openStep3TechModal(item);
        });

        // Right side: Segmented Options (3 compliance states)
        const inputs = document.createElement('div');
        inputs.className = 'vector-inputs';

        let currentOptionLabel = 'مشخص نشده';
        if (selectedValue !== undefined) {
            const foundOpt = item.options.find(o => o.value === selectedValue);
            if (foundOpt) currentOptionLabel = foundOpt.label;
        }

        inputs.innerHTML = `
            <div class="selector-label">
                <span>میزان آمادگی عملیاتی:</span>
                <span class="selector-status" id="s3-status-${item.id}">${currentOptionLabel}</span>
            </div>
            <div class="step2-segmented-group" id="s3-seg-${item.id}"></div>
        `;

        const segGroup = inputs.querySelector(`#s3-seg-${item.id}`);
        item.options.forEach(opt => {
            const btn = document.createElement('button');
            btn.type = 'button';
            const isSelected = selectedValue === opt.value;
            btn.className = `segment-btn ${isSelected ? `active-${opt.scoreType}` : ''}`;
            btn.textContent = opt.label;
            btn.title = opt.label;
            btn.addEventListener('click', () => setStep3Answer(item.id, opt.value));
            segGroup.appendChild(btn);
        });

        card.appendChild(main);
        card.appendChild(inputs);
        list.appendChild(card);
    });
}

function setStep3Answer(itemId, optionValue) {
    if (!auditState.step3Answers) auditState.step3Answers = {};
    auditState.step3Answers[itemId] = optionValue;
    persistState();

    // In-place DOM update
    const item = STEP3_ITEMS.find(i => i.id === itemId);
    const segGroup = document.getElementById(`s3-seg-${itemId}`);
    if (segGroup && item) {
        segGroup.querySelectorAll('.segment-btn').forEach((btn, idx) => {
            const opt = item.options[idx];
            if (opt) {
                btn.className = `segment-btn ${opt.value === optionValue ? `active-${opt.scoreType}` : ''}`;
            }
        });
    }
    const statusLabel = document.getElementById(`s3-status-${itemId}`);
    if (statusLabel && item) {
        const foundOpt = item.options.find(o => o.value === optionValue);
        if (foundOpt) statusLabel.textContent = foundOpt.label;
    }

    updateStep3Progress();
}

function calculateStep3() {
    const total = STEP3_ITEMS.length;
    let assessedCount = 0;
    let userWeightedScore = 0;
    let maxWeightedScore = 0;

    STEP3_ITEMS.forEach(item => {
        maxWeightedScore += (item.weight * 100);
        const val = auditState.step3Answers ? auditState.step3Answers[item.id] : undefined;
        if (val !== undefined) {
            assessedCount++;
            userWeightedScore += (item.weight * val);
        }
    });

    const score = maxWeightedScore > 0 ? Math.round((userWeightedScore / maxWeightedScore) * 100) : 0;
    const isComplete = assessedCount === total;
    return { total, assessedCount, score, isComplete };
}

function updateStep3Progress() {
    const calc = calculateStep3();
    auditState.step3Score = calc.score;

    const countElem = document.getElementById('step3AssessedCount');
    if (countElem) countElem.textContent = calc.assessedCount;
    const totalElem = document.getElementById('step3TotalCount');
    if (totalElem) totalElem.textContent = calc.total;

    const percent = Math.round((calc.assessedCount / calc.total) * 100);
    const bar = document.getElementById('step3ProgressBar');
    if (bar) bar.style.width = `${percent}%`;
    const label = document.getElementById('step3ProgressLabel');
    if (label) label.textContent = `${percent}% بررسی شده`;

    const scoreFooter = document.getElementById('footerStep3Score');
    if (scoreFooter) scoreFooter.textContent = calc.score;

    const completeBtn = document.getElementById('completeStep3Btn');
    const footerTitle = document.getElementById('footerStep3StatusTitle');
    const footerDesc = document.getElementById('footerStep3StatusDesc');

    if (completeBtn && footerTitle && footerDesc) {
        if (calc.isComplete) {
            completeBtn.disabled = false;
            footerTitle.textContent = 'تمام ۱۶ پروتکل مرحله ۳ بررسی شد';
            footerDesc.textContent = `امتیاز واکنش به بحران مرحله ۳: ${calc.score} از ۱۰۰. اکنون کارنامه جامع و شاخص کل تاب‌آوری آماده صدور است.`;
        } else {
            completeBtn.disabled = true;
            const remaining = calc.total - calc.assessedCount;
            footerTitle.textContent = `در حال بررسی (${calc.assessedCount} از ${calc.total} پروتکل)`;
            footerDesc.textContent = `هنوز ${remaining} پروتکل باقیمانده است. برای محاسبه شاخص کل، تمام موارد را مشخص نمایید.`;
        }
    }

    updateStepperUI();
}

function completeStep3() {
    const calc = calculateStep3();
    if (!calc.isComplete) {
        alert('لطفاً ابتدا تمام ۱۶ پروتکل مرحله ۳ را مشخص فرمایید.');
        return;
    }

    auditState.step3Completed = true;
    auditState.step3Score = calc.score;

    // Grand Overall Score: 30% S1 + 40% S2 + 30% S3
    auditState.overallScore = Math.round(
        (auditState.step1Score * 0.30) +
        (auditState.step2Score * 0.40) +
        (auditState.step3Score * 0.30)
    );

    auditState.auditDate = new Date().toISOString();
    auditState.activeStep = 4;
    persistState();

    switchToStep(4);
    showToast(`مرحله ۳ تکمیل شد و کارنامه نهایی صادر گردید (شاخص کل: ${auditState.overallScore} از ۱۰۰)`);
}

// -------------------------------------------------------------
// STEP 4 LOGIC (Executive Certificate & Action Plan)
// -------------------------------------------------------------

function initStep4EventListeners() {
    const printBtn = document.getElementById('printReportBtn');
    if (printBtn) {
        printBtn.addEventListener('click', () => {
            window.print();
        });
    }

    const copyBtn = document.getElementById('copyFinalReportBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyExecutiveSummary);
    }

    const reviewS1 = document.getElementById('reviewStep1Btn');
    if (reviewS1) reviewS1.addEventListener('click', () => switchToStep(1));

    const reviewS2 = document.getElementById('reviewStep2Btn');
    if (reviewS2) reviewS2.addEventListener('click', () => switchToStep(2));

    const reviewS3 = document.getElementById('reviewStep3Btn');
    if (reviewS3) reviewS3.addEventListener('click', () => switchToStep(3));

    const restartBtn = document.getElementById('restartFullAuditBtn');
    if (restartBtn) {
        restartBtn.addEventListener('click', () => {
            if (confirm('آیا از بازنشانی کلیه داده‌ها و شروع مجدد از مرحله ۱ اطمینان دارید؟ تمامی ارزیابی‌های شما پاک خواهد شد.')) {
                localStorage.removeItem(STORAGE_KEY);
                auditState = {
                    activeStep: 1,
                    step1Completed: false,
                    step1Score: 0,
                    step1Assessments: {},
                    step2Completed: false,
                    step2Score: 0,
                    step2Answers: {},
                    step3Completed: false,
                    step3Score: 0,
                    step3Answers: {},
                    overallScore: 0,
                    auditDate: null,
                    currentCategoryStep1: 'all',
                    searchQueryStep1: '',
                    currentCategoryStep2: 'all',
                    searchQueryStep2: '',
                    currentCategoryStep3: 'all',
                    searchQueryStep3: ''
                };
                persistState();
                renderStep1View();
                updateStep1Progress();
                renderStep2View();
                updateStep2Progress();
                renderStep3View();
                updateStep3Progress();
                updateStepperUI();
                switchToStep(1);
                showToast('پلتفرم با موفقیت به حالت اولیه بازنشانی شد.');
            }
        });
    }
}

function renderStep4View() {
    // Ensure overall score is calculated
    auditState.overallScore = Math.round(
        (auditState.step1Score * 0.30) +
        (auditState.step2Score * 0.40) +
        (auditState.step3Score * 0.30)
    );

    const scoreValElem = document.getElementById('finalOverallScoreVal');
    if (scoreValElem) scoreValElem.textContent = auditState.overallScore;

    const dateElem = document.getElementById('finalReportTimestamp');
    if (dateElem) {
        try {
            const dateObj = auditState.auditDate ? new Date(auditState.auditDate) : new Date();
            const dateStr = new Intl.DateTimeFormat('fa-IR', {
                year: 'numeric', month: 'long', day: 'numeric',
                hour: '2-digit', minute: '2-digit'
            }).format(dateObj);
            dateElem.textContent = `تاریخ ممیزی: ${dateStr}`;
        } catch (e) {
            dateElem.textContent = 'تاریخ ممیزی: ثبت شده';
        }
    }

    // Verdict, Tier badge & styling
    const tierBadge = document.getElementById('finalSecurityTierBadge');
    const verdictTitle = document.getElementById('finalVerdictTitle');
    const verdictDesc = document.getElementById('finalVerdictDesc');
    const grandHero = document.getElementById('grandScoreHero');

    const score = auditState.overallScore;

    if (score >= 85) {
        if (tierBadge) {
            tierBadge.textContent = 'سطح A+ // پایداری و تاب‌آوری حداکثری (Hardened)';
            tierBadge.style.background = 'rgba(16, 185, 129, 0.2)';
            tierBadge.style.color = '#10b981';
            tierBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
        }
        if (verdictTitle) verdictTitle.textContent = 'وضعیت امنیتی: بسیار مطلوب و مقاوم در برابر سرقت اطلاعات';
        if (verdictDesc) verdictDesc.textContent = 'سیستم شما از لایه‌های دفاع در عمق (Defense-in-Depth) برخوردار است. نگهداری پسوردها در نرم‌افزار اختصاصی و مستقل، غیرفعال بودن ذخیره خودکار مرورگر، فعال‌سازی تایید دومرحله‌ای مقاوم و پروتکل‌های ایزولاسیون شبکه در ثانیه‌های بحران، خطر نشت و مصادره نشست‌ها توسط استیلرها را به حداقل رسانده است.';
        if (grandHero) {
            grandHero.style.borderColor = 'rgba(16, 185, 129, 0.35)';
        }
    } else if (score >= 65) {
        if (tierBadge) {
            tierBadge.textContent = 'سطح B // تاب‌آوری متوسط و قابل قبول (Moderate)';
            tierBadge.style.background = 'rgba(245, 158, 11, 0.2)';
            tierBadge.style.color = '#fbbf24';
            tierBadge.style.borderColor = 'rgba(245, 158, 11, 0.4)';
        }
        if (verdictTitle) verdictTitle.textContent = 'وضعیت امنیتی: آگاهی مناسب اما نیازمند رفع چند روزنه بحرانی';
        if (verdictDesc) verdictDesc.textContent = 'پیکربندی عمومی شما در سطح قابل قبولی است، با این حال چند نقطه ضعف مشخص (مانند ذخیره برخی کوکی‌ها، فعال بودن Autofill یا تاخیر در ابطال سشن‌ها) می‌تواند در صورت مواجهه با استیلرهای سارقان مورد سوءاستفاده قرار گیرد. توصیه می‌شود اقدامات اصلاحی زیر را اجرا کنید.';
        if (grandHero) {
            grandHero.style.borderColor = 'rgba(245, 158, 11, 0.35)';
        }
    } else if (score >= 40) {
        if (tierBadge) {
            tierBadge.textContent = 'سطح C // آسیب‌پذیر و پرریسک (Vulnerable)';
            tierBadge.style.background = 'rgba(249, 115, 22, 0.2)';
            tierBadge.style.color = '#fb923c';
            tierBadge.style.borderColor = 'rgba(249, 115, 22, 0.4)';
        }
        if (verdictTitle) verdictTitle.textContent = 'وضعیت امنیتی: ریسک بالای نشت اطلاعات کاربری و نشست‌ها';
        if (verdictDesc) verdictDesc.textContent = 'سیستم در شرایط پرریسک قرار دارد. ذخیره‌سازی داده‌های حساس در مرورگر، ضعف در تمهیدات ۲FA یا عدم آمادگی برای واکنش فوری به بدافزار، خطر تخلیه والت‌های کریپتو و هک اکانت‌های پیام‌رسان را تشدید کرده است. اصلاح موارد بحرانی زیر اکیداً توصیه می‌شود.';
        if (grandHero) {
            grandHero.style.borderColor = 'rgba(249, 115, 22, 0.35)';
        }
    } else {
        if (tierBadge) {
            tierBadge.textContent = 'سطح D // بحرانی و آسیب‌پذیری فوری (Critical Exposure)';
            tierBadge.style.background = 'rgba(220, 38, 38, 0.2)';
            tierBadge.style.color = '#f87171';
            tierBadge.style.borderColor = 'rgba(220, 38, 38, 0.4)';
        }
        if (verdictTitle) verdictTitle.textContent = 'وضعیت امنیتی: وضعیت بحرانی و آسیب‌پذیری کامل در برابر استیلرها';
        if (verdictDesc) verdictDesc.textContent = 'سیستم شما در برابر نسل جدید استیلرها (مانند Lumma, RedLine, Vidar, Stealc) کاملاً بی‌پناه است. در صورت باز شدن یک فایل آلوده، تمام کوکی‌های لاگین، گذرواژه‌ها، کلیدهای والت و نشست‌های تلگرام ظرف چند ثانیه به سرور هکر مخابره خواهند شد.';
        if (grandHero) {
            grandHero.style.borderColor = 'rgba(220, 38, 38, 0.5)';
        }
    }

    // 3 Stage score pills
    const p1 = document.getElementById('finalStep1ScorePill');
    if (p1) p1.textContent = `${auditState.step1Score}%`;
    const p2 = document.getElementById('finalStep2ScorePill');
    if (p2) p2.textContent = `${auditState.step2Score}%`;
    const p3 = document.getElementById('finalStep3ScorePill');
    if (p3) p3.textContent = `${auditState.step3Score}%`;

    // Populate Remediation Directives Roadmap
    renderRemediationRoadmap();
}

function renderRemediationRoadmap() {
    const list = document.getElementById('finalRemediationList');
    const countLabel = document.getElementById('finalRemediationCountLabel');
    if (!list) return;
    list.innerHTML = '';

    const remediations = [];

    // Stage 1 Gaps
    STEALER_VECTORS.forEach(v => {
        const assessment = (auditState.step1Assessments && auditState.step1Assessments[v.id]) || { familiarity: null, isExposed: false };
        if (assessment.familiarity === 0) {
            remediations.push({
                phase: 1,
                phaseLabel: 'مرحله ۱: بردار نفوذ',
                priority: 'critical',
                title: v.title,
                subtitle: v.subtitle,
                impact: `عدم شناخت مکانیزم این بردار ورود (${v.prevalence}).`,
                action: v.defenseTips[0] || 'مطالعه و پیاده‌سازی تمهیدات پیشگیرانه در این بردار.'
            });
        } else if (assessment.familiarity === 35 || assessment.isExposed) {
            remediations.push({
                phase: 1,
                phaseLabel: 'مرحله ۱: بردار نفوذ',
                priority: 'high',
                title: v.title,
                subtitle: v.subtitle,
                impact: assessment.isExposed ? `سابقه فعالیت یا حضور در محیط این بردار (${v.prevalence}).` : 'آشنایی صرفاً سطحی و ناکافی با شیوه نفوذ.',
                action: v.defenseTips[0] || 'مطالعه و پیاده‌سازی تمهیدات پیشگیرانه در این بردار.'
            });
        }
    });

    // Stage 2 Gaps
    STEP2_ITEMS.forEach(item => {
        const val = auditState.step2Answers ? auditState.step2Answers[item.id] : undefined;
        if (val === 0) {
            remediations.push({
                phase: 2,
                phaseLabel: 'مرحله ۲: دارایی و سیستم',
                priority: 'critical',
                title: item.title,
                subtitle: item.subtitle,
                impact: item.technicalImpact,
                action: item.remediation
            });
        } else if (val !== undefined && val < 100) {
            remediations.push({
                phase: 2,
                phaseLabel: 'مرحله ۲: دارایی و سیستم',
                priority: 'high',
                title: item.title,
                subtitle: item.subtitle,
                impact: item.technicalImpact,
                action: item.remediation
            });
        }
    });

    // Stage 3 Gaps
    STEP3_ITEMS.forEach(item => {
        const val = auditState.step3Answers ? auditState.step3Answers[item.id] : undefined;
        if (val === 0) {
            remediations.push({
                phase: 3,
                phaseLabel: 'مرحله ۳: مهار و بازیابی',
                priority: 'critical',
                title: item.title,
                subtitle: item.subtitle,
                impact: item.technicalImpact,
                action: item.remediation
            });
        } else if (val !== undefined && val < 100) {
            remediations.push({
                phase: 3,
                phaseLabel: 'مرحله ۳: مهار و بازیابی',
                priority: 'high',
                title: item.title,
                subtitle: item.subtitle,
                impact: item.technicalImpact,
                action: item.remediation
            });
        }
    });

    // Sort: critical first, then high, then phase
    remediations.sort((a, b) => {
        if (a.priority === 'critical' && b.priority !== 'critical') return -1;
        if (a.priority !== 'critical' && b.priority === 'critical') return 1;
        return a.phase - b.phase;
    });

    if (countLabel) {
        countLabel.textContent = `${remediations.length} مورد نیازمند اصلاح و ارتقاء`;
    }

    if (remediations.length === 0) {
        list.innerHTML = `
            <div class="clean-pass-card">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <polyline points="9 12 11 14 15 10"></polyline>
                </svg>
                <h4 style="font-size: 1.15rem; font-weight: 800; color: #a7f3d0;">تبریک! هیچ آسیب‌پذیری بحرانی یا نقص امنیتی یافت نشد</h4>
                <p style="font-size: 0.85rem; color: var(--text-secondary); max-width: 540px; line-height: 1.6;">
                    تمامی مؤلفه‌ها در ۶۴ شاخص امنیتی بررسی‌شده در بالاترین سطح استاندارد ارزیابی شده‌اند. برای حفظ این آمادگی، بررسی‌های دوره‌ای را ادامه دهید.
                </p>
            </div>
        `;
        return;
    }

    remediations.forEach(r => {
        const card = document.createElement('div');
        card.className = `remediation-card priority-${r.priority}`;
        card.innerHTML = `
            <div class="remediation-meta">
                <span class="remediation-step-pill">${r.phaseLabel}</span>
                <span class="vector-severity-tag severity-${r.priority}">
                    ${r.priority === 'critical' ? 'اولویت بحرانی' : 'اولویت بالا'}
                </span>
            </div>
            <div class="remediation-title-row">
                <div class="remediation-title">${r.title}</div>
                <span class="vector-subtitle">${r.subtitle}</span>
            </div>
            <div class="remediation-impact">${r.impact}</div>
            <div class="remediation-action-box">
                <svg class="remediation-action-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
                <div class="remediation-action-text"><strong>دستورالعمل اقدام: </strong>${r.action}</div>
            </div>
        `;
        list.appendChild(card);
    });
}

function copyExecutiveSummary() {
    let dateStr = 'ثبت شده';
    try {
        const dateObj = auditState.auditDate ? new Date(auditState.auditDate) : new Date();
        dateStr = new Intl.DateTimeFormat('fa-IR', {
            year: 'numeric', month: 'long', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        }).format(dateObj);
    } catch(e) {}

    let tierLabel = 'سطح نامشخص';
    if (auditState.overallScore >= 85) tierLabel = 'A+ (Hardened - حداکثر پایداری)';
    else if (auditState.overallScore >= 65) tierLabel = 'B (Moderate - آمادگی متوسط)';
    else if (auditState.overallScore >= 40) tierLabel = 'C (Vulnerable - پرریسک)';
    else tierLabel = 'D (Critical Exposure - بحرانی)';

    const text = `====================================================
گزارش جامع ممیزی پلتفرم آنتی‌استیلر (Anti-Stealer)
کد گزارش: AS-SEC-2026 // تاریخ: ${dateStr}
====================================================
شاخص کل تاب‌آوری سایبری: ${auditState.overallScore} از ۱۰۰
رتبه امنیتی: ${tierLabel}

--- کارنامه تفکیکی مراحل سه‌گانه ---
۱. شناخت راه‌های نفوذ و مهندسی اجتماعی: ${auditState.step1Score}% (وزن ۳۰٪)
۲. استحکام دارایی‌ها، فایل‌ها و سیستم‌عامل: ${auditState.step2Score}% (وزن ۴۰٪)
۳. مهار نفوذ، ابطال سشن‌ها و واکنش به بحران: ${auditState.step3Score}% (وزن ۳۰٪)

تعداد کل مؤلفه‌های ممیزی‌شده: ۶۴ مؤلفه امنیتی
====================================================
Anti-Stealer Security Platform • Enterprise Zero-Trust Framework`;

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('متن گزارش رسمی در کلیپ‌بورد کپی شد');
        }).catch(() => {
            showToast('خطا در کپی به کلیپ‌بورد');
        });
    } else {
        showToast('امکان کپی خودکار فراهم نیست');
    }
}

// -------------------------------------------------------------
// NAVIGATION & STEPPER MANAGEMENT
// -------------------------------------------------------------

function updateStepperUI() {
    // Step 1 Stepper
    const step1Nav = document.getElementById('stepNavItem-1');
    const step1Badge = document.getElementById('stepBadge-1');
    const step1Status = document.getElementById('stepStatus-1');

    if (auditState.step1Completed) {
        step1Nav.className = 'step-item completed';
        step1Badge.innerHTML = '✓';
        step1Status.textContent = `تکمیل شد (${auditState.step1Score}%)`;
    } else {
        step1Nav.className = auditState.activeStep === 1 ? 'step-item active' : 'step-item';
        step1Badge.textContent = '۱';
        step1Status.textContent = 'در حال ارزیابی';
    }

    // Step 2 Stepper
    const step2Nav = document.getElementById('stepNavItem-2');
    const step2Badge = document.getElementById('stepBadge-2');
    const step2Status = document.getElementById('stepStatus-2');

    if (auditState.step2Completed) {
        step2Nav.className = 'step-item completed';
        step2Badge.innerHTML = '✓';
        step2Status.textContent = `تکمیل شد (${auditState.step2Score}%)`;
    } else if (auditState.activeStep === 2) {
        step2Nav.className = 'step-item active';
        step2Badge.textContent = '۲';
        step2Status.textContent = 'مرحله جاری';
    } else if (!auditState.step1Completed) {
        step2Nav.className = 'step-item';
        step2Badge.textContent = '۲';
        step2Status.textContent = 'قفل شده';
    } else {
        step2Nav.className = 'step-item';
        step2Badge.textContent = '۲';
        step2Status.textContent = 'آماده شروع';
    }

    // Step 3 Stepper
    const step3Nav = document.getElementById('stepNavItem-3');
    const step3Badge = document.getElementById('stepBadge-3');
    const step3Status = document.getElementById('stepStatus-3');

    if (auditState.step3Completed) {
        step3Nav.className = 'step-item completed';
        step3Badge.innerHTML = '✓';
        step3Status.textContent = `تکمیل شد (${auditState.step3Score}%)`;
    } else if (auditState.activeStep === 3) {
        step3Nav.className = 'step-item active';
        step3Badge.textContent = '۳';
        step3Status.textContent = 'مرحله جاری';
    } else if (!auditState.step2Completed) {
        step3Nav.className = 'step-item';
        step3Badge.textContent = '۳';
        step3Status.textContent = 'قفل شده';
    } else {
        step3Nav.className = 'step-item';
        step3Badge.textContent = '۳';
        step3Status.textContent = 'آماده شروع';
    }

    // Step 4 Stepper
    const step4Nav = document.getElementById('stepNavItem-4');
    const step4Badge = document.getElementById('stepBadge-4');
    const step4Status = document.getElementById('stepStatus-4');

    if (auditState.step3Completed && auditState.activeStep === 4) {
        step4Nav.className = 'step-item active';
        step4Badge.textContent = 'Σ';
        step4Status.textContent = `کارنامه کل صادر شد (${auditState.overallScore}%)`;
    } else if (auditState.step3Completed) {
        step4Nav.className = 'step-item completed';
        step4Badge.textContent = 'Σ';
        step4Status.textContent = `کارنامه آماده (${auditState.overallScore}%)`;
    } else {
        step4Nav.className = 'step-item';
        step4Badge.textContent = 'Σ';
        step4Status.textContent = 'مرحله پایانی';
    }
}

function switchToStep(stepNumber) {
    auditState.activeStep = stepNumber;
    persistState();

    const view1 = document.getElementById('step1View');
    const view2 = document.getElementById('step2View');
    const view3 = document.getElementById('step3View');
    const view4 = document.getElementById('step4View');

    if (view1) view1.style.display = stepNumber === 1 ? 'block' : 'none';
    if (view2) view2.style.display = stepNumber === 2 ? 'block' : 'none';
    if (view3) view3.style.display = stepNumber === 3 ? 'block' : 'none';
    if (view4) view4.style.display = stepNumber === 4 ? 'block' : 'none';

    if (stepNumber === 1) {
        renderStep1View();
        updateStep1Progress();
    } else if (stepNumber === 2) {
        const textElem = document.getElementById('step1ConfirmedScoreText');
        if (textElem) textElem.textContent = `امتیاز مرحله ۱: ${auditState.step1Score} از ۱۰۰`;
        renderStep2View();
        updateStep2Progress();
    } else if (stepNumber === 3) {
        const textElem = document.getElementById('step1And2ScoresText');
        if (textElem) textElem.textContent = `مرحله ۱: ${auditState.step1Score}% | مرحله ۲: ${auditState.step2Score}%`;
        renderStep3View();
        updateStep3Progress();
    } else if (stepNumber === 4) {
        renderStep4View();
    }

    updateStepperUI();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// -------------------------------------------------------------
// TECHNICAL MODALS
// -------------------------------------------------------------

function openStep1TechModal(vector) {
    const modal = document.getElementById('techModal');
    const catMeta = VECTOR_CATEGORIES[vector.category] || { label: 'عمومی' };

    document.getElementById('modalCategoryTag').textContent = `${catMeta.label} • ${vector.severity.toUpperCase()}`;
    document.getElementById('modalTitle').textContent = vector.title;
    document.getElementById('modalSubtitle').textContent = vector.subtitle;
    document.getElementById('modalMechanism').textContent = vector.mechanism;

    // Show malware block
    document.getElementById('modalMalwareBlock').style.display = 'block';
    const tagsContainer = document.getElementById('modalMalwareTags');
    tagsContainer.innerHTML = '';
    vector.realWorldMalware.forEach(name => {
        const tag = document.createElement('span');
        tag.className = 'intel-tag';
        tag.textContent = name;
        tagsContainer.appendChild(tag);
    });

    // Red Flags
    document.getElementById('modalRedFlagsBlock').style.display = 'block';
    const redFlagsList = document.getElementById('modalRedFlags');
    redFlagsList.innerHTML = '';
    vector.redFlags.forEach(f => {
        const li = document.createElement('li');
        li.textContent = f;
        redFlagsList.appendChild(li);
    });

    // Defenses
    const defensesList = document.getElementById('modalDefenses');
    defensesList.innerHTML = '';
    vector.defenseTips.forEach(d => {
        const li = document.createElement('li');
        li.textContent = d;
        defensesList.appendChild(li);
    });

    modal.classList.add('active');
}

function openStep2TechModal(item) {
    const modal = document.getElementById('techModal');
    const catMeta = STEP2_CATEGORIES[item.category] || { label: 'پیکربندی سیستم' };

    document.getElementById('modalCategoryTag').textContent = `${catMeta.label} • ضریب ریسک ${item.weight}X`;
    document.getElementById('modalTitle').textContent = item.title;
    document.getElementById('modalSubtitle').textContent = item.subtitle;
    document.getElementById('modalMechanism').textContent = item.technicalImpact;

    // Hide Step 1 specific blocks
    document.getElementById('modalMalwareBlock').style.display = 'none';
    document.getElementById('modalRedFlagsBlock').style.display = 'none';

    // Show Remediation Directive
    const defensesList = document.getElementById('modalDefenses');
    defensesList.innerHTML = '';
    const li = document.createElement('li');
    li.textContent = item.remediation;
    defensesList.appendChild(li);

    modal.classList.add('active');
}

function openStep3TechModal(item) {
    const modal = document.getElementById('techModal');
    const catMeta = STEP3_CATEGORIES[item.category] || { label: 'واکنش به حادثه' };

    document.getElementById('modalCategoryTag').textContent = `${catMeta.label} • ضریب ریسک ${item.weight}X`;
    document.getElementById('modalTitle').textContent = item.title;
    document.getElementById('modalSubtitle').textContent = item.subtitle;
    document.getElementById('modalMechanism').textContent = item.technicalImpact;

    // Hide Step 1 specific blocks
    document.getElementById('modalMalwareBlock').style.display = 'none';
    document.getElementById('modalRedFlagsBlock').style.display = 'none';

    // Show Remediation Directive
    const defensesList = document.getElementById('modalDefenses');
    defensesList.innerHTML = '';
    const li = document.createElement('li');
    li.textContent = item.remediation;
    defensesList.appendChild(li);

    modal.classList.add('active');
}

function closeTechModal() {
    const modal = document.getElementById('techModal');
    if (modal) modal.classList.remove('active');
}

function showToast(msg) {
    const toast = document.getElementById('toastNotice');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('active');
    setTimeout(() => {
        toast.classList.remove('active');
    }, 2500);
}
