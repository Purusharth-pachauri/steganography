document.addEventListener('DOMContentLoaded', () => {
    // --- UI Elements ---
    const tabs = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    const encodeDropzone = document.getElementById('encode-dropzone');
    const encodeInput = document.getElementById('encode-image-input');
    const encodePreview = document.getElementById('encode-image-preview');
    const encodeMessage = document.getElementById('encode-message');
    const encodePassword = document.getElementById('encode-password');
    const btnEncode = document.getElementById('btn-encode');
    const encodeSuccess = document.getElementById('encode-success');
    const encodeError = document.getElementById('encode-error');
    const encodeErrorMsg = document.getElementById('encode-error-msg');

    const decodeDropzone = document.getElementById('decode-dropzone');
    const decodeInput = document.getElementById('decode-image-input');
    const decodePreview = document.getElementById('decode-image-preview');
    const decodePassword = document.getElementById('decode-password');
    const btnDecode = document.getElementById('btn-decode');
    const decodeResultBox = document.getElementById('decode-result-box');
    const decodeResult = document.getElementById('decode-result');
    const decodeError = document.getElementById('decode-error');
    const decodeErrorMsg = document.getElementById('decode-error-msg');

    const internalCanvas = document.getElementById('internal-canvas');
    const ctx = internalCanvas.getContext('2d', { willReadFrequently: true });

    let currentEncodeImage = null;
    let currentDecodeImage = null;

    // --- Tab Switching ---
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');
            
            // Reset states
            encodeSuccess.classList.add('hidden');
            encodeError.classList.add('hidden');
            decodeError.classList.add('hidden');
            decodeResultBox.classList.add('hidden');
        });
    });

    // --- File Handling (Drag & Drop + Click) ---
    function setupDropzone(dropzone, input, preview, isEncode) {
        dropzone.addEventListener('click', () => input.click());
        
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('dragover');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                handleFile(e.dataTransfer.files[0], preview, isEncode);
            }
        });

        input.addEventListener('change', (e) => {
            if (e.target.files.length) {
                handleFile(e.target.files[0], preview, isEncode);
            }
        });
    }

    function handleFile(file, previewElement, isEncode) {
        if (!file.type.match('image.*')) {
            showError(isEncode, 'Please select a valid image file.');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                previewElement.src = img.src;
                previewElement.style.display = 'block';
                if (isEncode) {
                    currentEncodeImage = img;
                    encodeSuccess.classList.add('hidden');
                    encodeError.classList.add('hidden');
                } else {
                    currentDecodeImage = img;
                    decodeError.classList.add('hidden');
                    decodeResultBox.classList.add('hidden');
                }
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }

    setupDropzone(encodeDropzone, encodeInput, encodePreview, true);
    setupDropzone(decodeDropzone, decodeInput, decodePreview, false);

    // --- Crypto Engine ---
    const cryptoSubtle = window.crypto.subtle;

    async function getPasswordKey(password) {
        const enc = new TextEncoder();
        const keyMaterial = await cryptoSubtle.importKey(
            "raw",
            enc.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );
        return cryptoSubtle.deriveKey(
            {
                name: "PBKDF2",
                salt: enc.encode("stegovault_static_salt"), // Static salt to allow decryption later
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptData(text, password) {
        const key = await getPasswordKey(password);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedText = new TextEncoder().encode(text);
        
        const encrypted = await cryptoSubtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encodedText
        );
        
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encrypted), iv.length);
        return result; // IV + Cipher
    }

    async function decryptData(encryptedDataArray, password) {
        const key = await getPasswordKey(password);
        const iv = encryptedDataArray.slice(0, 12);
        const cipherText = encryptedDataArray.slice(12);
        
        try {
            const decrypted = await cryptoSubtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                cipherText
            );
            return new TextDecoder().decode(decrypted);
        } catch (e) {
            throw new Error("Incorrect password or corrupted image.");
        }
    }

    // --- Steganography Engine ---
    async function encode() {
        if (!currentEncodeImage) return showError(true, "Please upload an image first.");
        const text = encodeMessage.value.trim();
        const password = encodePassword.value;
        
        if (!text) return showError(true, "Please enter a secret message.");
        if (!password) return showError(true, "Please enter a security key.");

        setLoading(btnEncode, true);
        encodeSuccess.classList.add('hidden');
        encodeError.classList.add('hidden');

        try {
            // 1. Encrypt payload
            const encryptedBytes = await encryptData(text, password);
            
            // 2. Convert to bits
            const payloadBits = [];
            for (let i = 0; i < encryptedBytes.length; i++) {
                for (let j = 7; j >= 0; j--) {
                    payloadBits.push((encryptedBytes[i] >> j) & 1);
                }
            }

            // 3. Length prefix (32 bits)
            const length = payloadBits.length;
            const lengthBits = [];
            for (let i = 31; i >= 0; i--) {
                lengthBits.push((length >> i) & 1);
            }

            const allBits = [...lengthBits, ...payloadBits];

            // 4. Draw to canvas
            const width = currentEncodeImage.width;
            const height = currentEncodeImage.height;
            internalCanvas.width = width;
            internalCanvas.height = height;
            ctx.drawImage(currentEncodeImage, 0, 0);

            const imgData = ctx.getImageData(0, 0, width, height);
            const data = imgData.data;

            // 3 channels per pixel (RGB, skip Alpha)
            const capacity = (width * height) * 3;
            if (allBits.length > capacity) {
                throw new Error("Image is too small to hold this amount of text. Use a larger image or shorter text.");
            }

            let bitIndex = 0;
            for (let i = 0; i < data.length; i++) {
                if ((i + 1) % 4 === 0) continue; // Skip alpha
                
                if (bitIndex < allBits.length) {
                    // Clear LSB and set to our bit
                    data[i] = (data[i] & ~1) | allBits[bitIndex];
                    bitIndex++;
                } else {
                    break;
                }
            }

            ctx.putImageData(imgData, 0, 0);

            // 5. Download the encoded image
            internalCanvas.toBlob((blob) => {
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'stego_encrypted.png';
                a.click();
                URL.revokeObjectURL(url);
                showSuccess();
            }, 'image/png');

        } catch (error) {
            showError(true, error.message || "An error occurred during encryption.");
        } finally {
            setLoading(btnEncode, false);
        }
    }

    async function decode() {
        if (!currentDecodeImage) return showError(false, "Please upload an image first.");
        const password = decodePassword.value;
        
        if (!password) return showError(false, "Please enter the security key.");

        setLoading(btnDecode, true);
        decodeError.classList.add('hidden');
        decodeResultBox.classList.add('hidden');

        try {
            // 1. Draw to canvas
            const width = currentDecodeImage.width;
            const height = currentDecodeImage.height;
            internalCanvas.width = width;
            internalCanvas.height = height;
            ctx.drawImage(currentDecodeImage, 0, 0);

            const imgData = ctx.getImageData(0, 0, width, height);
            const data = imgData.data;

            // 2. Read first 32 bits for length
            let lengthBits = [];
            let i = 0;
            while(lengthBits.length < 32 && i < data.length) {
                 if ((i + 1) % 4 !== 0) {
                     lengthBits.push(data[i] & 1);
                 }
                 i++;
            }

            if (lengthBits.length < 32) throw new Error("Image doesn't contain valid steganography data.");

            let length = 0;
            for(let j=0; j<32; j++) {
                length = (length << 1) | lengthBits[j];
            }

            // Sanity check length
            const maxPayloadBits = (width * height * 3) - 32;
            if (length <= 0 || length > maxPayloadBits || length > 5000000) { // Limit reasonable text size
                throw new Error("No steganography data found or the image is corrupted.");
            }
            if (length % 8 !== 0) {
                 throw new Error("Invalid steganography data.");
            }

            // 3. Read payload bits
            let payloadBits = new Uint8Array(length);
            let ptr = 0;
            while(ptr < length && i < data.length) {
                if ((i + 1) % 4 !== 0) {
                    payloadBits[ptr++] = data[i] & 1;
                }
                i++;
            }

            if (ptr < length) throw new Error("Image data is incomplete.");

            // 4. Convert bits to bytes
            const encryptedBytes = new Uint8Array(length / 8);
            for(let k=0; k < length; k+=8) {
                let byte = 0;
                for(let j=0; j<8; j++) {
                    byte = (byte << 1) | payloadBits[k+j];
                }
                encryptedBytes[k/8] = byte;
            }

            // 5. Decrypt
            const decryptedText = await decryptData(encryptedBytes, password);
            
            // Show result
            decodeResult.textContent = decryptedText;
            decodeResultBox.classList.remove('hidden');

        } catch (error) {
            showError(false, error.message || "An error occurred during decryption.");
        } finally {
            setLoading(btnDecode, false);
        }
    }

    // --- Helpers ---
    function showError(isEncode, message) {
        if (isEncode) {
            encodeErrorMsg.textContent = message;
            encodeError.classList.remove('hidden');
        } else {
            decodeErrorMsg.textContent = message;
            decodeError.classList.remove('hidden');
        }
    }

    function showSuccess() {
        encodeSuccess.classList.remove('hidden');
        encodeMessage.value = '';
        encodePassword.value = '';
    }

    function setLoading(btn, isLoading) {
        if (isLoading) {
            btn.classList.add('loading');
            btn.disabled = true;
        } else {
            btn.classList.remove('loading');
            btn.disabled = false;
        }
    }

    // --- Event Listeners ---
    btnEncode.addEventListener('click', encode);
    btnDecode.addEventListener('click', decode);
});
