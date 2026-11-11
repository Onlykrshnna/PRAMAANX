/**
 * PRAMAANX - useUpload Hook
 * Manages the client-side evidence file queue, format/size validation, duplicate prevention,
 * and thumbnail object URL lifecycles.
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { FORENSIC_LIMITS, SUPPORTED_EXTENSIONS } from '../utils/constants';
import { formatBytes } from '../utils/formatters';

const IMAGE_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif']);
const DOCUMENT_EXTENSIONS = new Set(['.pdf']);
const OFFICE_EXTENSIONS = new Set(['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt']);
const ARCHIVE_EXTENSIONS = new Set(['.zip']);

function getExtension(filename) {
  const lastDot = filename.lastIndexOf('.');
  if (lastDot === -1) return '';
  return filename.slice(lastDot).toLowerCase();
}

function getTypeCategory(ext) {
  if (IMAGE_EXTENSIONS.has(ext)) return 'image';
  if (DOCUMENT_EXTENSIONS.has(ext)) return 'document';
  if (OFFICE_EXTENSIONS.has(ext)) return 'office';
  if (ARCHIVE_EXTENSIONS.has(ext)) return 'archive';
  return 'other';
}

export function useUpload() {
  const [files, setFiles] = useState([]);
  const [errors, setErrors] = useState([]);
  const filesRef = useRef(files);

  // Sync ref inside effect to satisfy react-hooks/refs
  useEffect(() => {
    filesRef.current = files;
  }, [files]);

  const addError = useCallback((errorMessage) => {
    setErrors((prev) => [...prev, errorMessage]);
  }, []);

  const clearErrors = useCallback(() => {
    setErrors([]);
  }, []);

  const removeError = useCallback((indexToRemove) => {
    setErrors((prev) => prev.filter((_, idx) => idx !== indexToRemove));
  }, []);

  const removeFile = useCallback((idToRemove) => {
    setFiles((prev) => {
      const target = prev.find((item) => item.id === idToRemove);
      if (target && target.thumbnailUrl) {
        URL.revokeObjectURL(target.thumbnailUrl);
      }
      return prev.filter((item) => item.id !== idToRemove);
    });
  }, []);

  const clearQueue = useCallback(() => {
    filesRef.current.forEach((item) => {
      if (item.thumbnailUrl) {
        URL.revokeObjectURL(item.thumbnailUrl);
      }
    });
    setFiles([]);
    setErrors([]);
  }, []);

  const addFiles = useCallback((incomingFiles) => {
    if (!incomingFiles || incomingFiles.length === 0) return;

    const fileArray = Array.from(incomingFiles);
    const newErrors = [];
    const validNewItems = [];

    const currentFiles = filesRef.current;
    const availableSlots = FORENSIC_LIMITS.MAX_BATCH_FILES - currentFiles.length;

    if (availableSlots <= 0) {
      setErrors((prev) => [
        ...prev,
        `Queue limit reached. Maximum ${FORENSIC_LIMITS.MAX_BATCH_FILES} files allowed per analysis session.`,
      ]);
      return;
    }

    let acceptedCount = 0;

    for (const rawFile of fileArray) {
      const ext = getExtension(rawFile.name);

      // 1. Empty file validation
      if (rawFile.size === 0) {
        newErrors.push(`"${rawFile.name}" was rejected because the file is empty (0 bytes).`);
        continue;
      }

      // 2. Format validation
      if (!SUPPORTED_EXTENSIONS.includes(ext)) {
        newErrors.push(
          `"${rawFile.name}" has an unsupported format (${ext || 'no extension'}). Supported: PDF, Office (DOCX, XLSX, PPTX, legacy), Images (JPG, PNG, BMP, TIFF), and ZIP.`
        );
        continue;
      }

      // 3. Individual file size limit (20 MB)
      if (rawFile.size > FORENSIC_LIMITS.MAX_SINGLE_FILE_BYTES) {
        newErrors.push(
          `"${rawFile.name}" exceeds the 20 MB file size limit (${formatBytes(rawFile.size)}).`
        );
        continue;
      }

      // 4. Duplicate file check (same name + same byte size)
      const isDuplicateInCurrent = currentFiles.some(
        (item) => item.name === rawFile.name && item.size === rawFile.size
      );
      const isDuplicateInBatch = validNewItems.some(
        (item) => item.name === rawFile.name && item.size === rawFile.size
      );

      if (isDuplicateInCurrent || isDuplicateInBatch) {
        newErrors.push(`"${rawFile.name}" is already in the analysis queue.`);
        continue;
      }

      // 5. Batch file capacity limit
      if (acceptedCount >= availableSlots) {
        newErrors.push(
          `Maximum ${FORENSIC_LIMITS.MAX_BATCH_FILES} files allowed. Remaining files were not added.`
        );
        break;
      }

      // Create thumbnail for images
      const category = getTypeCategory(ext);
      let thumbnailUrl = null;
      if (category === 'image') {
        try {
          thumbnailUrl = URL.createObjectURL(rawFile);
        } catch {
          thumbnailUrl = null;
        }
      }

      validNewItems.push({
        id: `${rawFile.name}-${rawFile.size}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        file: rawFile,
        name: rawFile.name,
        size: rawFile.size,
        extension: ext,
        typeCategory: category,
        thumbnailUrl,
        status: 'ready',
      });

      acceptedCount += 1;
    }

    if (newErrors.length > 0) {
      setErrors((prev) => [...prev, ...newErrors]);
    }

    if (validNewItems.length > 0) {
      setFiles((prev) => [...prev, ...validNewItems]);
    }
  }, []);

  const totalBytes = files.reduce((acc, item) => acc + item.size, 0);

  return {
    files,
    errors,
    addFiles,
    removeFile,
    clearQueue,
    addError,
    removeError,
    clearErrors,
    totalCount: files.length,
    totalBytes,
    hasFiles: files.length > 0,
    isFull: files.length >= FORENSIC_LIMITS.MAX_BATCH_FILES,
  };
}
