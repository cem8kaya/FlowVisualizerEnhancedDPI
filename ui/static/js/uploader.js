// File Upload Handler

const uploader = {
    dropZone: null,
    fileInput: null,
    currentUpload: null,

    init() {
        this.dropZone = document.getElementById('dropZone');
        this.fileInput = document.getElementById('fileInput');
        const browseBtn = document.getElementById('browseBtn');

        if (!this.dropZone || !this.fileInput) return;

        // Browse button click
        browseBtn.addEventListener('click', () => {
            this.fileInput.click();
        });

        // File input change
        this.fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFiles(e.target.files);
            }
        });

        // Drag and drop events
        this.dropZone.addEventListener('click', (e) => {
            if (!e.target.closest('button')) {
                this.fileInput.click();
            }
        });

        this.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.dropZone.classList.add('drag-over');
        });

        this.dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            this.dropZone.classList.remove('drag-over');
        });

        this.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            this.dropZone.classList.remove('drag-over');

            if (e.dataTransfer.files.length > 0) {
                this.handleFiles(e.dataTransfer.files);
            }
        });
    },

    handleFiles(files) {
        if (files.length === 0) return;

        const file = files[0];

        // Validate file
        if (!this.validateFile(file)) {
            return;
        }

        this.uploadFile(file);
    },

    validateFile(file) {
        // Check file extension
        const validExtensions = ['.pcap', '.pcapng', '.cap'];
        const fileName = file.name.toLowerCase();
        const hasValidExtension = validExtensions.some(ext => fileName.endsWith(ext));

        if (!hasValidExtension) {
            app.showToast('Please upload a valid PCAP file (.pcap, .pcapng, .cap)', 'error');
            return false;
        }

        // Check file size (max 10GB)
        const maxSize = 10 * 1024 * 1024 * 1024; // 10GB in bytes
        if (file.size > maxSize) {
            app.showToast('File size exceeds maximum limit of 10GB', 'error');
            return false;
        }

        return true;
    },

    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);

        // Show uploading state
        this.showUploadProgress(file);

        try {
            const xhr = new XMLHttpRequest();

            // Upload progress
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    this.updateProgress(percent);
                }
            });

            // Upload complete
            xhr.addEventListener('load', () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    const response = JSON.parse(xhr.responseText);
                    this.onUploadSuccess(response);
                } else {
                    this.onUploadError(xhr.statusText);
                }
            });

            // Upload error
            xhr.addEventListener('error', () => {
                this.onUploadError('Upload failed');
            });

            // Upload abort
            xhr.addEventListener('abort', () => {
                this.onUploadError('Upload cancelled');
            });

            xhr.open('POST', API_BASE + '/upload');
            xhr.send(formData);

            this.currentUpload = xhr;

        } catch (error) {
            this.onUploadError(error.message);
        }
    },

    showUploadProgress(file) {
        const content = this.dropZone.querySelector('.drop-zone-content');
        const uploading = this.dropZone.querySelector('.drop-zone-uploading');

        content.style.display = 'none';
        uploading.style.display = 'block';

        document.getElementById('uploadFileName').textContent = file.name;
        document.getElementById('uploadSize').textContent = app.formatBytes(file.size);
        this.updateProgress(0);
    },

    updateProgress(percent) {
        const progressBar = document.getElementById('uploadProgress');
        progressBar.style.width = percent + '%';
        progressBar.textContent = percent + '%';
    },

    onUploadSuccess(response) {
        app.showToast('File uploaded successfully! Processing started.', 'success');
        console.log('Upload response:', response);

        // Reset UI
        this.resetUploadUI();

        // Reload jobs table
        if (typeof jobsTable !== 'undefined') {
            jobsTable.loadJobs();
        }

        // If job_id is returned, optionally navigate to it
        if (response.job_id) {
            // Connect to WebSocket for real-time updates
            // if (typeof wsHandler !== 'undefined') {
            //     wsHandler.connect(response.job_id);
            // }
        }
    },

    onUploadError(error) {
        app.showToast(`Upload failed: ${error}`, 'error');
        console.error('Upload error:', error);
        this.resetUploadUI();
    },

    resetUploadUI() {
        const content = this.dropZone.querySelector('.drop-zone-content');
        const uploading = this.dropZone.querySelector('.drop-zone-uploading');

        content.style.display = 'block';
        uploading.style.display = 'none';

        this.fileInput.value = '';
        this.currentUpload = null;
    }
};

// Initialize uploader on page load
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('dropZone')) {
        uploader.init();
    }
});
