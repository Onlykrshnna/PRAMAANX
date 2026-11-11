/**
 * PRAMAANX - Forensic Metadata Extraction & Normalization Helpers
 * ===============================================================
 * "Simple to understand. Deep enough to investigate."
 *
 * Provides standardized, file-type-aware metadata reporting:
 * - Images: EXIF, Camera Make/Model, Timestamps, Dimensions, GPS, Orientation, Software, ICC/Color Space.
 * - PDFs: Author, Title, Subject, Creator, Producer, CreationDate, ModDate, XMP Metadata.
 * - Office: Author (creator), Last modified by, Created/Modified timestamps, Application properties, Company, Title, Subject.
 * - ZIP Archives: Entry names, Timestamps, Compression methods, CRC32, Archive properties.
 *
 * Scientific Core Principles:
 * 1. Missing metadata is NOT classified as suspicious (privacy-preserving apps routinely strip metadata).
 * 2. Embedded timestamps reflect unauthenticated local device clocks and must not be assumed trustworthy.
 * 3. Never fabricate missing or unreadable values.
 * 4. Distinguish filesystem timestamps from embedded container metadata timestamps.
 * 5. Sanitize and escape potentially unsafe metadata strings before display.
 */

/**
 * Escapes potentially unsafe metadata strings to prevent XSS and strip control characters.
 */
export function sanitizeMetadataValue(val) {
  if (val === null || val === undefined) return '';
  if (typeof val === 'boolean' || typeof val === 'number') return String(val);

  let str = typeof val === 'object' ? JSON.stringify(val) : String(val);

  // Strip non-printable ASCII control characters (except tab, newline, and carriage return)
  str = Array.from(str)
    .filter((ch) => {
      const code = ch.charCodeAt(0);
      return code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127);
    })
    .join('');

  // HTML entity escaping for script/tag injection prevention
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Evaluates the status of an extracted metadata value:
 * - 'Available': Valid non-empty value present
 * - 'Missing': Expected field was not present in the artifact
 * - 'Unreadable': Value exists but is corrupted, unparseable, or erroneous
 * - 'Not examined': Field is not supported or not evaluated by the current analyzer
 */
export function determineFieldStatus(value, isSupported = true) {
  if (!isSupported) {
    return 'Not examined';
  }
  if (value === null || value === undefined || value === '') {
    return 'Missing';
  }
  if (typeof value === 'string' && (value.includes('\uFFFD') || value.toLowerCase().includes('corrupt') || value.toLowerCase().includes('unreadable'))) {
    return 'Unreadable';
  }
  return 'Available';
}

/**
 * Normalizes and extracts structured metadata fields according to file format.
 */
export function buildMetadataReport(fileType, detectedMime, rawMetadata = {}, fileInfo = {}) {
  const normType = String(fileType || '').toLowerCase();
  const normMime = String(detectedMime || '').toLowerCase();

  const isPdf = normType.includes('pdf') || normMime.includes('pdf');
  const isDocx = normType.includes('docx') || normMime.includes('wordprocessingml');
  const isXlsx = normType.includes('xlsx') || normMime.includes('spreadsheetml');
  const isPptx = normType.includes('pptx') || normMime.includes('presentationml');
  const isOffice =
    isDocx ||
    isXlsx ||
    isPptx ||
    normType.includes('office') ||
    normMime.includes('officedocument') ||
    normMime.includes('ole');
  const isZip = normType.includes('zip') || normMime.includes('zip') || normType.includes('archive');
  const isImage =
    normType.includes('jpg') ||
    normType.includes('jpeg') ||
    normType.includes('png') ||
    normType.includes('bmp') ||
    normType.includes('tiff') ||
    normType.includes('image') ||
    normMime.startsWith('image/');

  const fields = [];

  // ===========================================================================
  // 1. IMAGE METADATA
  // ===========================================================================
  if (isImage) {
    const make = rawMetadata.camera_make || rawMetadata.Make || null;
    const model = rawMetadata.camera_model || rawMetadata.Model || null;
    const makeModelVal = make || model ? [make, model].filter(Boolean).join(' ') : null;

    fields.push({
      id: 'img_camera',
      name: 'Camera / Device Model',
      value: makeModelVal,
      status: determineFieldStatus(makeModelVal),
      source: 'EXIF / IFD0 (0x010F & 0x0110)',
      isTimestamp: false,
      description: 'Hardware camera or scanner manufacturer and model designation.',
    });

    const dtOrig = rawMetadata.datetime_original || rawMetadata.DateTimeOriginal || null;
    fields.push({
      id: 'img_dt_orig',
      name: 'DateTimeOriginal (Capture)',
      value: dtOrig,
      status: determineFieldStatus(dtOrig),
      source: 'EXIF / SubIFD (0x9003)',
      isTimestamp: true,
      description: 'Timestamp when original image was captured by camera sensor.',
    });

    const dtDigitized = rawMetadata.datetime_digitized || rawMetadata.DateTimeDigitized || null;
    fields.push({
      id: 'img_dt_digitized',
      name: 'DateTimeDigitized',
      value: dtDigitized,
      status: determineFieldStatus(dtDigitized),
      source: 'EXIF / SubIFD (0x9004)',
      isTimestamp: true,
      description: 'Timestamp when image was stored as digital data.',
    });

    const dt = rawMetadata.datetime || rawMetadata.DateTime || null;
    fields.push({
      id: 'img_dt',
      name: 'DateTime (File Modified)',
      value: dt,
      status: determineFieldStatus(dt),
      source: 'EXIF / IFD0 (0x0132)',
      isTimestamp: true,
      description: 'Timestamp of last modification recorded in EXIF header.',
    });

    const gps = rawMetadata.gps_coordinates || (rawMetadata.GPSCoordinates ? String(rawMetadata.GPSCoordinates) : null);
    fields.push({
      id: 'img_gps',
      name: 'GPS Geolocation Coordinates',
      value: gps,
      status: determineFieldStatus(gps),
      source: 'EXIF / GPSInfo SubIFD (0x8825)',
      isTimestamp: false,
      description: 'Geographic latitude, longitude, and elevation embedded by GPS sensor.',
    });

    const dims = rawMetadata.dimensions || (rawMetadata.width && rawMetadata.height ? `${rawMetadata.width} × ${rawMetadata.height}` : null);
    fields.push({
      id: 'img_dimensions',
      name: 'Image Dimensions (Pixel Geometry)',
      value: dims,
      status: determineFieldStatus(dims),
      source: 'Image Container Header',
      isTimestamp: false,
      description: 'Physical horizontal and vertical raster pixel resolution.',
    });

    const orient = rawMetadata.orientation || rawMetadata.Orientation || null;
    fields.push({
      id: 'img_orientation',
      name: 'Orientation',
      value: orient ? `Code ${orient}` : null,
      status: determineFieldStatus(orient),
      source: 'EXIF / IFD0 (0x0112)',
      isTimestamp: false,
      description: 'Display rotation tag specifying how sensor was held during capture.',
    });

    const software = rawMetadata.software || rawMetadata.Software || null;
    fields.push({
      id: 'img_software',
      name: 'Software / Editor Attribution',
      value: software,
      status: determineFieldStatus(software),
      source: 'EXIF / IFD0 (0x0131)',
      isTimestamp: false,
      description: 'Firmware or photo editing software that saved or retouched this image.',
    });

    const colorSpace = rawMetadata.color_space || rawMetadata.color_mode || null;
    const iccInfo = rawMetadata.has_icc_profile ? `Embedded ICC Profile (${rawMetadata.icc_profile_size || 'custom'} bytes)` : 'No Embedded ICC Profile';
    const colorDesc = colorSpace ? `${colorSpace} • ${iccInfo}` : (rawMetadata.has_icc_profile ? iccInfo : null);

    fields.push({
      id: 'img_color_profile',
      name: 'Color Space & ICC Profile',
      value: colorDesc,
      status: determineFieldStatus(colorDesc),
      source: 'Container Color Table & ICC Header',
      isTimestamp: false,
      description: 'Color calibration model and embedded International Color Consortium profile.',
    });

  // ===========================================================================
  // 2. PDF METADATA
  // ===========================================================================
  } else if (isPdf) {
    const author = rawMetadata.author || null;
    fields.push({
      id: 'pdf_author',
      name: 'Author',
      value: author,
      status: determineFieldStatus(author),
      source: 'PDF /Info Dictionary',
      isTimestamp: false,
      description: 'Identity of the person or principal who created the document.',
    });

    const title = rawMetadata.title || null;
    fields.push({
      id: 'pdf_title',
      name: 'Document Title',
      value: title,
      status: determineFieldStatus(title),
      source: 'PDF /Info Dictionary',
      isTimestamp: false,
      description: 'Declared title of the document.',
    });

    const subject = rawMetadata.subject || null;
    fields.push({
      id: 'pdf_subject',
      name: 'Subject / Summary',
      value: subject,
      status: determineFieldStatus(subject),
      source: 'PDF /Info Dictionary',
      isTimestamp: false,
      description: 'Subject matter or topical categorization.',
    });

    const creator = rawMetadata.creator || null;
    fields.push({
      id: 'pdf_creator',
      name: 'Creator Application',
      value: creator,
      status: determineFieldStatus(creator),
      source: 'PDF /Info Dictionary',
      isTimestamp: false,
      description: 'Original application that authored the document content (e.g. Word, InDesign).',
    });

    const producer = rawMetadata.producer || null;
    fields.push({
      id: 'pdf_producer',
      name: 'Producer Engine',
      value: producer,
      status: determineFieldStatus(producer),
      source: 'PDF /Info Dictionary',
      isTimestamp: false,
      description: 'PDF library or print converter that rendered the final PDF byte stream.',
    });

    const created = rawMetadata.creation_date_iso || rawMetadata.creation_date_raw || null;
    fields.push({
      id: 'pdf_created',
      name: 'CreationDate (Embedded)',
      value: created,
      status: determineFieldStatus(created),
      source: 'PDF /Info Dictionary (/CreationDate)',
      isTimestamp: true,
      description: 'Embedded creation date specified in PDF 1.7 date format.',
    });

    const modified = rawMetadata.mod_date_iso || rawMetadata.mod_date_raw || null;
    fields.push({
      id: 'pdf_modified',
      name: 'ModDate (Embedded)',
      value: modified,
      status: determineFieldStatus(modified),
      source: 'PDF /Info Dictionary (/ModDate)',
      isTimestamp: true,
      description: 'Embedded timestamp of most recent document modification.',
    });

    const xmp = rawMetadata.has_xmp ? 'Present (Extensible Metadata Platform stream)' : (rawMetadata.xmp_metadata ? 'Present' : null);
    fields.push({
      id: 'pdf_xmp',
      name: 'XMP Extensible Metadata Stream',
      value: xmp,
      status: determineFieldStatus(xmp),
      source: 'PDF Catalog /Metadata XML Stream',
      isTimestamp: false,
      description: 'ISO 16684-1 XML metadata stream containing Dublin Core schemas.',
    });

  // ===========================================================================
  // 3. OFFICE DOCUMENT METADATA
  // ===========================================================================
  } else if (isOffice) {
    const creator = rawMetadata.creator || rawMetadata.author || null;
    fields.push({
      id: 'office_author',
      name: 'Author (Creator)',
      value: creator,
      status: determineFieldStatus(creator),
      source: 'docProps/core.xml (dc:creator)',
      isTimestamp: false,
      description: 'Primary author username or identity credited in document properties.',
    });

    const lastMod = rawMetadata.last_modified_by || null;
    fields.push({
      id: 'office_last_mod_by',
      name: 'Last Modified By',
      value: lastMod,
      status: determineFieldStatus(lastMod),
      source: 'docProps/core.xml (cp:lastModifiedBy)',
      isTimestamp: false,
      description: 'Username of the person who executed the last document save.',
    });

    const created = rawMetadata.created_iso || rawMetadata.created_raw || null;
    fields.push({
      id: 'office_created',
      name: 'Created Timestamp (Embedded)',
      value: created,
      status: determineFieldStatus(created),
      source: 'docProps/core.xml (dcterms:created)',
      isTimestamp: true,
      description: 'ISO 8601 timestamp recorded when document container was initialized.',
    });

    const modified = rawMetadata.modified_iso || rawMetadata.modified_raw || null;
    fields.push({
      id: 'office_modified',
      name: 'Modified Timestamp (Embedded)',
      value: modified,
      status: determineFieldStatus(modified),
      source: 'docProps/core.xml (dcterms:modified)',
      isTimestamp: true,
      description: 'ISO 8601 timestamp recorded when document container was last saved.',
    });

    const app = rawMetadata.application || null;
    const appVer = rawMetadata.app_version ? `(v${rawMetadata.app_version})` : '';
    const appVal = app ? `${app} ${appVer}`.trim() : null;
    fields.push({
      id: 'office_application',
      name: 'Application Properties',
      value: appVal,
      status: determineFieldStatus(appVal),
      source: 'docProps/app.xml (Application / AppVersion)',
      isTimestamp: false,
      description: 'Software suite and build version used to produce the Office package.',
    });

    const company = rawMetadata.company || null;
    fields.push({
      id: 'office_company',
      name: 'Company / Organization',
      value: company,
      status: determineFieldStatus(company),
      source: 'docProps/app.xml (Company)',
      isTimestamp: false,
      description: 'Organization name registered in the editing workstation license.',
    });

    const title = rawMetadata.title || null;
    fields.push({
      id: 'office_title',
      name: 'Document Title',
      value: title,
      status: determineFieldStatus(title),
      source: 'docProps/core.xml (dc:title)',
      isTimestamp: false,
      description: 'Declared title of the Office document.',
    });

    const subject = rawMetadata.subject || null;
    fields.push({
      id: 'office_subject',
      name: 'Subject Matter',
      value: subject,
      status: determineFieldStatus(subject),
      source: 'docProps/core.xml (dc:subject)',
      isTimestamp: false,
      description: 'Declared subject or category of document contents.',
    });

  // ===========================================================================
  // 4. ZIP ARCHIVE METADATA
  // ===========================================================================
  } else if (isZip) {
    const entries = Array.isArray(rawMetadata.entries) ? rawMetadata.entries : [];
    const entryNames = entries.length > 0 ? entries.slice(0, 8).map((e) => e.name).join(', ') + (entries.length > 8 ? ` (+${entries.length - 8} more)` : '') : null;

    fields.push({
      id: 'zip_entry_names',
      name: 'Member Entry Names',
      value: entryNames,
      status: determineFieldStatus(entryNames),
      source: 'PKWare Central Directory Header (0x02014B50)',
      isTimestamp: false,
      description: 'Internal member relative path filenames contained in archive.',
    });

    const timestamps = entries.length > 0 ? entries.slice(0, 4).map((e) => `${e.name}: ${e.timestamp}`).join('; ') : null;
    fields.push({
      id: 'zip_timestamps',
      name: 'Entry Modification Timestamps',
      value: timestamps,
      status: determineFieldStatus(timestamps),
      source: 'PKWare Local File Headers (MS-DOS Date/Time)',
      isTimestamp: true,
      description: 'Legacy MS-DOS 32-bit modification timestamps stored with each entry.',
    });

    const methods = entries.length > 0 ? Array.from(new Set(entries.map((e) => e.compress_type))).join(', ') : null;
    fields.push({
      id: 'zip_compression_methods',
      name: 'Compression Methods',
      value: methods,
      status: determineFieldStatus(methods),
      source: 'PKWare Central Directory (Compression Field)',
      isTimestamp: false,
      description: 'Compression algorithms utilized (e.g. Deflate method 8, Store method 0).',
    });

    const crcs = entries.length > 0 ? entries.slice(0, 4).map((e) => `${e.name}: ${e.crc32}`).join('; ') : null;
    fields.push({
      id: 'zip_crc32',
      name: 'Cyclic Redundancy Checks (CRC32)',
      value: crcs,
      status: determineFieldStatus(crcs),
      source: 'PKWare Local Headers & Central Directory (CRC-32)',
      isTimestamp: false,
      description: '32-bit polynomial check values for verifying data transfer integrity.',
    });

    const comment = rawMetadata.comment || null;
    fields.push({
      id: 'zip_comment',
      name: 'Archive Comment',
      value: comment,
      status: determineFieldStatus(comment),
      source: 'End of Central Directory Record (EOCD 0x06054B50)',
      isTimestamp: false,
      description: 'Text string appended to End of Central Directory record.',
    });
  } else {
    // Generic fallback for other supported or binary files
    fields.push({
      id: 'generic_container',
      name: 'Container Format',
      value: fileInfo.detected_type ? fileInfo.detected_type.toUpperCase() : 'Unknown',
      status: 'Available',
      source: 'Binary Header Magic Bytes',
      isTimestamp: false,
      description: 'Detected file format signature.',
    });
  }

  // Compute overview metrics
  const availableCount = fields.filter((f) => f.status === 'Available').length;
  const missingCount = fields.filter((f) => f.status === 'Missing').length;
  const unreadableCount = fields.filter((f) => f.status === 'Unreadable').length;
  const notExaminedCount = fields.filter((f) => f.status === 'Not examined').length;
  const totalExamined = fields.length;

  return {
    formatCategory: isImage ? 'Image' : isPdf ? 'PDF' : isOffice ? 'Office Document' : isZip ? 'ZIP Archive' : 'File Container',
    fields,
    overview: {
      totalExamined,
      availableCount,
      missingCount,
      unreadableCount,
      notExaminedCount,
    },
    rawMetadata,
  };
}
