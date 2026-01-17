/**
 * Audio Transcription Module using Groq Whisper API
 * 
 * This module provides automatic transcription of audio messages
 * received via WhatsApp using Groq's fast Whisper API.
 * 
 * @author Alucard0x1
 * @see https://console.groq.com/docs/speech-to-text
 */

const Groq = require('groq-sdk');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class AudioTranscriber {
    constructor() {
        this.groq = null;
        this.enabled = false;
        this.model = process.env.GROQ_WHISPER_MODEL || 'whisper-large-v3-turbo';
        this.defaultLanguage = process.env.GROQ_WHISPER_LANGUAGE || null; // ISO 639-1: 'es', 'en', 'pt', etc.
        this.tempDir = path.join(__dirname, 'temp_audio');
        
        this.initialize();
    }

    initialize() {
        const apiKey = process.env.GROQ_API_KEY;
        const enableTranscription = process.env.ENABLE_AUDIO_TRANSCRIPTION !== 'false';

        if (apiKey && enableTranscription) {
            try {
                this.groq = new Groq({ apiKey });
                this.enabled = true;
                this.ensureTempDir();
                console.log('🎤 Audio transcription enabled (Groq Whisper API)');
                console.log(`   Model: ${this.model}`);
                console.log(`   Language: ${this.defaultLanguage || 'auto-detect'}`);
            } catch (error) {
                console.error('❌ Failed to initialize Groq client:', error.message);
                this.enabled = false;
            }
        } else {
            if (!apiKey) {
                console.log('ℹ️  Audio transcription disabled (GROQ_API_KEY not set)');
            } else {
                console.log('ℹ️  Audio transcription disabled by configuration');
            }
        }
    }

    ensureTempDir() {
        if (!fs.existsSync(this.tempDir)) {
            fs.mkdirSync(this.tempDir, { recursive: true });
        }
    }

    /**
     * Check if transcription is available
     */
    isEnabled() {
        return this.enabled && this.groq !== null;
    }

    /**
     * Detect message type from WhatsApp message object
     * @param {Object} message - WhatsApp message object from Baileys
     * @returns {Object} - { type: string, hasAudio: boolean, hasMedia: boolean, messageContent: Object }
     */
    detectMessageType(message) {
        if (!message || !message.message) {
            return { type: 'unknown', hasAudio: false, hasMedia: false, messageContent: null };
        }

        const msg = message.message;

        // Check for audio message (voice note or audio file)
        if (msg.audioMessage) {
            return {
                type: 'audio',
                hasAudio: true,
                hasMedia: true,
                isVoiceNote: msg.audioMessage.ptt === true,
                messageContent: msg.audioMessage,
                mimetype: msg.audioMessage.mimetype,
                duration: msg.audioMessage.seconds
            };
        }

        // Check for video message (might contain audio)
        if (msg.videoMessage) {
            return {
                type: 'video',
                hasAudio: true,
                hasMedia: true,
                messageContent: msg.videoMessage,
                mimetype: msg.videoMessage.mimetype,
                duration: msg.videoMessage.seconds,
                caption: msg.videoMessage.caption || null
            };
        }

        // Check for image
        if (msg.imageMessage) {
            return { 
                type: 'image', 
                hasAudio: false, 
                hasMedia: true,
                messageContent: msg.imageMessage,
                mimetype: msg.imageMessage.mimetype,
                caption: msg.imageMessage.caption || null,
                width: msg.imageMessage.width,
                height: msg.imageMessage.height
            };
        }

        // Check for sticker
        if (msg.stickerMessage) {
            return { 
                type: 'sticker', 
                hasAudio: false, 
                hasMedia: true,
                messageContent: msg.stickerMessage,
                mimetype: msg.stickerMessage.mimetype,
                isAnimated: msg.stickerMessage.isAnimated || false
            };
        }

        // Check for document
        if (msg.documentMessage) {
            return { 
                type: 'document', 
                hasAudio: false, 
                hasMedia: true,
                messageContent: msg.documentMessage,
                mimetype: msg.documentMessage.mimetype,
                filename: msg.documentMessage.fileName,
                fileSize: msg.documentMessage.fileLength
            };
        }

        // Check for text message
        if (msg.conversation) {
            return { type: 'text', hasAudio: false, hasMedia: false, messageContent: msg.conversation };
        }

        if (msg.extendedTextMessage) {
            return { type: 'text', hasAudio: false, hasMedia: false, messageContent: msg.extendedTextMessage.text };
        }

        return { type: 'unknown', hasAudio: false, hasMedia: false, messageContent: null };
    }

    /**
     * Download media from WhatsApp message
     * @param {Object} sock - Baileys socket instance
     * @param {Object} message - WhatsApp message object
     * @returns {Promise<Buffer>} - Audio buffer
     */
    async downloadMedia(sock, message) {
        const { downloadMediaMessage } = require('@whiskeysockets/baileys');
        
        try {
            const buffer = await downloadMediaMessage(
                message,
                'buffer',
                {},
                {
                    logger: console,
                    reuploadRequest: sock.updateMediaMessage
                }
            );
            return buffer;
        } catch (error) {
            console.error('Error downloading media:', error.message);
            throw error;
        }
    }

    /**
     * Transcribe audio buffer using Groq Whisper API
     * @param {Buffer} audioBuffer - Audio data buffer
     * @param {string} mimetype - MIME type of the audio (e.g., 'audio/ogg; codecs=opus')
     * @param {string} language - Optional language hint (ISO 639-1, e.g., 'es', 'en')
     * @returns {Promise<Object>} - Transcription result
     */
    async transcribe(audioBuffer, mimetype = 'audio/ogg', language = null) {
        if (!this.isEnabled()) {
            throw new Error('Audio transcription is not enabled');
        }

        const tempFilePath = path.join(
            this.tempDir,
            `audio_${crypto.randomBytes(8).toString('hex')}.ogg`
        );

        try {
            // Write buffer to temp file
            fs.writeFileSync(tempFilePath, audioBuffer);

            // Create transcription request
            const transcriptionOptions = {
                file: fs.createReadStream(tempFilePath),
                model: this.model,
                response_format: 'verbose_json',
                temperature: 0
            };

            // Add language hint if provided, otherwise use default (improves accuracy)
            const langToUse = language || this.defaultLanguage;
            if (langToUse) {
                transcriptionOptions.language = langToUse;
            }

            const startTime = Date.now();
            const transcription = await this.groq.audio.transcriptions.create(transcriptionOptions);
            const processingTime = Date.now() - startTime;

            return {
                success: true,
                text: transcription.text,
                language: transcription.language,
                duration: transcription.duration,
                processingTimeMs: processingTime,
                segments: transcription.segments || [],
                model: this.model
            };

        } catch (error) {
            console.error('Transcription error:', error.message);
            return {
                success: false,
                error: error.message,
                text: null
            };
        } finally {
            // Clean up temp file
            if (fs.existsSync(tempFilePath)) {
                fs.unlinkSync(tempFilePath);
            }
        }
    }

    /**
     * Process a WhatsApp message and transcribe if it contains audio
     * @param {Object} sock - Baileys socket instance
     * @param {Object} message - WhatsApp message object
     * @param {string} sessionId - Session identifier
     * @returns {Promise<Object>} - Enhanced message data with transcription and audio base64
     */
    async processMessage(sock, message, sessionId) {
        const msgInfo = this.detectMessageType(message);
        
        const result = {
            type: msgInfo.type,
            hasAudio: msgInfo.hasAudio,
            transcription: null,
            isVoiceNote: msgInfo.isVoiceNote || false,
            duration: msgInfo.duration || null,
            mimetype: msgInfo.mimetype || null,
            base64: null,
            fileSizeKB: null
        };

        // If message has audio
        if (msgInfo.hasAudio) {
            try {
                console.log(`🎵 [${sessionId}] Downloading audio...`);
                const audioBuffer = await this.downloadMedia(sock, message);
                
                // Convert to Base64 for webhook
                result.base64 = audioBuffer.toString('base64');
                result.fileSizeKB = Math.round(audioBuffer.length / 1024);
                console.log(`📦 [${sessionId}] Audio size: ${result.fileSizeKB}KB`);

                // Transcribe if enabled
                if (this.isEnabled()) {
                    console.log(`🎤 [${sessionId}] Transcribing audio (${msgInfo.duration || '?'}s)...`);
                    const transcription = await this.transcribe(audioBuffer, msgInfo.mimetype);
                    
                    if (transcription.success) {
                        console.log(`✅ [${sessionId}] Transcription complete in ${transcription.processingTimeMs}ms`);
                        console.log(`   Text: "${transcription.text.substring(0, 100)}${transcription.text.length > 100 ? '...' : ''}"`);
                        result.transcription = transcription;
                    } else {
                        console.log(`❌ [${sessionId}] Transcription failed: ${transcription.error}`);
                        result.transcription = { success: false, error: transcription.error };
                    }
                }
            } catch (error) {
                console.error(`❌ [${sessionId}] Error processing audio:`, error.message);
                result.transcription = { success: false, error: error.message };
            }
        }

        return result;
    }

    /**
     * Process image/sticker/document message and return base64
     * @param {Object} sock - Baileys socket instance
     * @param {Object} message - WhatsApp message object
     * @param {string} sessionId - Session identifier
     * @returns {Promise<Object>} - Media data with base64
     */
    async processImage(sock, message, sessionId) {
        const msgInfo = this.detectMessageType(message);
        
        const result = {
            type: msgInfo.type,
            mimetype: msgInfo.mimetype || null,
            caption: msgInfo.caption || null,
            width: msgInfo.width || null,
            height: msgInfo.height || null,
            filename: msgInfo.filename || null,
            isAnimated: msgInfo.isAnimated || false,
            base64: null,
            fileSizeKB: null
        };

        try {
            console.log(`📷 [${sessionId}] Downloading ${msgInfo.type}...`);
            const mediaBuffer = await this.downloadMedia(sock, message);
            
            result.base64 = mediaBuffer.toString('base64');
            result.fileSizeKB = Math.round(mediaBuffer.length / 1024);
            console.log(`📦 [${sessionId}] ${msgInfo.type} size: ${result.fileSizeKB}KB`);
            
        } catch (error) {
            console.error(`❌ [${sessionId}] Error downloading ${msgInfo.type}:`, error.message);
            result.error = error.message;
        }

        return result;
    }

    /**
     * Get transcription statistics
     */
    getStats() {
        return {
            enabled: this.enabled,
            model: this.model,
            tempDir: this.tempDir
        };
    }
}

module.exports = AudioTranscriber;
