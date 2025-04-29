// Template data
const templates = {
    attack: {
        header_length: 1000,
        protocol_type: 6,
        duration: 0.1,
        rate: 1000,
        srate: 1000,
        drate: 0,
        fin_flag: 0,
        syn_flag: 1,
        rst_flag: 0,
        psh_flag: 0,
        ack_flag: 0,
        ece_flag: 0,
        cwr_flag: 0,
        ack_count: 0,
        syn_count: 1000,
        fin_count: 0,
        rst_count: 0,
        http: 0,
        https: 0,
        dns: 0,
        telnet: 0,
        smtp: 0,
        ssh: 0,
        irc: 0,
        tcp: 1,
        udp: 0,
        dhcp: 0,
        arp: 0,
        icmp: 0,
        igmp: 0,
        ipv: 0,
        llc: 0,
        tot_sum: 1000,
        min: 0,
        max: 1000,
        avg: 500,
        std: 500,
        tot_size: 1000,
        iat: 1,
        number: 1000,
        magnitude: 1000,
        radius: 1000,
        covariance: 1000,
        variance: 1000,
        weight: 1000
    },
    normal: {
        header_length: 20,
        protocol_type: 6,
        duration: 1.0,
        rate: 10,
        srate: 5,
        drate: 5,
        fin_flag: 0,
        syn_flag: 0,
        rst_flag: 0,
        psh_flag: 0,
        ack_flag: 1,
        ece_flag: 0,
        cwr_flag: 0,
        ack_count: 10,
        syn_count: 1,
        fin_count: 0,
        rst_count: 0,
        http: 1,
        https: 0,
        dns: 0,
        telnet: 0,
        smtp: 0,
        ssh: 0,
        irc: 0,
        tcp: 1,
        udp: 0,
        dhcp: 0,
        arp: 0,
        icmp: 0,
        igmp: 0,
        ipv: 0,
        llc: 0,
        tot_sum: 100,
        min: 0,
        max: 100,
        avg: 50,
        std: 25,
        tot_size: 100,
        iat: 0.1,
        number: 10,
        magnitude: 100,
        radius: 100,
        covariance: 100,
        variance: 100,
        weight: 100
    }
};

// Function to fill form with template data
function fillForm(template) {
    // Fill number inputs
    Object.entries(template).forEach(([key, value]) => {
        const input = document.querySelector(`input[name="${key}"]`);
        if (input && input.type !== 'hidden') {
            input.value = value;
        }
    });

    // Set Yes/No toggles
    document.querySelectorAll('.yes-no-toggle').forEach(toggle => {
        const hiddenInput = toggle.nextElementSibling;
        const buttons = toggle.querySelectorAll('.btn');
        const value = template[hiddenInput.name];
        
        buttons.forEach(button => {
            button.classList.remove('active');
            if (button.dataset.value === value.toString()) {
                button.classList.add('active');
            }
        });
        hiddenInput.value = value;
    });
}

// Initialize Yes/No toggles
document.querySelectorAll('.yes-no-toggle').forEach(toggle => {
    const buttons = toggle.querySelectorAll('.btn');
    const hiddenInput = toggle.nextElementSibling;
    
    buttons.forEach(button => {
        button.addEventListener('click', () => {
            buttons.forEach(b => b.classList.remove('active'));
            button.classList.add('active');
            hiddenInput.value = button.dataset.value;
        });
    });
});

// Reset form function
function resetForm() {
    // Reset all number inputs
    document.querySelectorAll('input[type="number"]').forEach(input => {
        input.value = '';
    });
    
    // Reset all Yes/No toggles
    document.querySelectorAll('.yes-no-toggle').forEach(toggle => {
        const buttons = toggle.querySelectorAll('.btn');
        const hiddenInput = toggle.nextElementSibling;
        
        buttons.forEach(button => {
            button.classList.remove('active');
            if (button.dataset.value === '0') {
                button.classList.add('active');
            }
        });
        hiddenInput.value = '0';
    });
    
    // Hide result container
    document.getElementById('resultContainer').style.display = 'none';
}

// Add event listener for reset button
document.getElementById('resetForm').addEventListener('click', resetForm);

// Add event listeners for template buttons
document.getElementById('attackTemplate').addEventListener('click', () => {
    fillForm(templates.attack);
});

document.getElementById('normalTemplate').addEventListener('click', () => {
    fillForm(templates.normal);
});

// Form submission handler
document.getElementById('detectionForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const data = {};
    formData.forEach((value, key) => data[key] = value);
    
    fetch('/predict', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const resultModal = new bootstrap.Modal(document.getElementById('resultModal'));
        const threatLevel = data.threat_level;
        const status = data.status;
        const warning = data.warning;
        
        // Update threat level
        document.getElementById('threatLevel').textContent = threatLevel.toFixed(4);
        const threatLevelBar = document.getElementById('threatLevelBar');
        threatLevelBar.style.width = `${threatLevel * 100}%`;
        
        // Update status and colors
        const statusBadge = document.getElementById('status');
        const navStatus = document.getElementById('nav-status');
        const statusTab = document.querySelector('.status-tab');
        
        // Set colors and icons based on threat level
        if (threatLevel > 0.7) {
            threatLevelBar.style.backgroundColor = 'var(--danger-color)';
            statusBadge.style.backgroundColor = 'var(--danger-color)';
            statusTab.style.backgroundColor = 'var(--danger-color)';
            statusBadge.innerHTML = '<i class="fas fa-exclamation-circle"></i><span>' + status + '</span>';
        } else if (threatLevel > 0.3) {
            threatLevelBar.style.backgroundColor = 'var(--warning-color)';
            statusBadge.style.backgroundColor = 'var(--warning-color)';
            statusTab.style.backgroundColor = 'var(--warning-color)';
            statusBadge.innerHTML = '<i class="fas fa-exclamation-triangle"></i><span>' + status + '</span>';
        } else {
            threatLevelBar.style.backgroundColor = 'var(--success-color)';
            statusBadge.style.backgroundColor = 'var(--success-color)';
            statusTab.style.backgroundColor = 'var(--success-color)';
            statusBadge.innerHTML = '<i class="fas fa-check-circle"></i><span>' + status + '</span>';
        }
        
        // Update status text
        statusBadge.querySelector('span').textContent = status;
        navStatus.textContent = status;
        
        // Update warning message
        const warningElement = document.getElementById('warning');
        if (warning) {
            warningElement.textContent = warning;
            warningElement.parentElement.style.display = 'flex';
        } else {
            warningElement.parentElement.style.display = 'none';
        }
        
        // Show modal
        resultModal.show();
    })
    .catch(error => {
        console.error('Error:', error);
        const resultModal = new bootstrap.Modal(document.getElementById('resultModal'));
        const statusTab = document.querySelector('.status-tab');
        
        document.getElementById('threatLevel').textContent = 'Error';
        document.getElementById('threatLevelBar').style.width = '0%';
        document.getElementById('threatLevelBar').style.backgroundColor = 'var(--danger-color)';
        
        const statusBadge = document.getElementById('status');
        statusBadge.innerHTML = '<i class="fas fa-times-circle"></i><span>Error</span>';
        statusBadge.style.backgroundColor = 'var(--danger-color)';
        
        statusTab.style.backgroundColor = 'var(--danger-color)';
        document.getElementById('nav-status').textContent = 'Error';
        
        document.getElementById('warning').textContent = 'Error: ' + error.message;
        resultModal.show();
    });
}); 