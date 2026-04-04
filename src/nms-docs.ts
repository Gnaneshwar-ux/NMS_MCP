import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { HandledError } from "./utils.js";

const DEFAULT_NMS_BOOKS_URL =
  process.env.MCP_NMS_DOCS_BOOKS_URL?.trim() ||
  "https://docs.oracle.com/en/industries/energy-water/network-management-system/books.html";
const DEFAULT_NMS_CACHE_DIR =
  process.env.MCP_NMS_DOCS_CACHE_DIR?.trim() ||
  path.resolve(os.homedir(), "Documents", "nms-docs");

const VERSION_GUIDES_PATH_PATTERN = /(?:^|\/)(nms_[^/]+?_guides\.html)$/i;
const GUIDE_JSON_PATTERN =
  /<script\b[^>]*id=["']book-data["'][^>]*>\s*([\s\S]*?)\s*<\/script>/i;
const LINK_PATTERN = /<a\b[^>]*href=["']([^"'#]+)["'][^>]*>([\s\S]*?)<\/a>/gi;

export interface NmsGuideSummary {
  title: string;
  slug: string;
  description: string;
  category: string;
  pdfUrl: string;
  htmlUrl: string;
  pdfFileName: string;
  cached: boolean;
  cachedPdfPath: string | null;
}

export interface NmsVersionSummary {
  version: string;
  versionShort: string;
  versionKey: string;
  guidesPageUrl: string;
  guideCount: number;
  guides: NmsGuideSummary[];
}

export interface ListNmsGuidesResult {
  sourceBooksUrl: string;
  cacheDir: string;
  versionCount: number;
  versions: NmsVersionSummary[];
}

export interface ResolveNmsGuidePdfResult {
  sourceBooksUrl: string;
  sourceGuidesPageUrl: string;
  cacheDir: string;
  version: string;
  versionShort: string;
  versionKey: string;
  guideTitle: string;
  guideSlug: string;
  pdfUrl: string;
  htmlUrl: string;
  pdfFileName: string;
  cached: boolean;
  downloaded: boolean;
  pdfPath: string;
  fileSizeBytes: number;
  contentSha256: string;
}

interface RawGuideEntry {
  title?: string;
  description?: string;
  category?: string;
  pdf?: string;
  html?: string;
}

interface VersionLink {
  version: string;
  versionShort: string;
  versionKey: string;
  guidesPageUrl: string;
}

interface FetchOptions {
  fetchImpl?: typeof fetch;
  booksUrl?: string;
  cacheDir?: string;
}

interface GuideMatchOptions extends FetchOptions {
  versionQuery?: string;
}

interface ResolveGuideOptions extends GuideMatchOptions {
  guideQuery: string;
  refresh?: boolean;
}

function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function stripHtml(value: string): string {
  return normalizeWhitespace(
    value
      .replace(/<[^>]+>/g, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&nbsp;/gi, " ")
      .replace(/&#39;/gi, "'")
      .replace(/&quot;/gi, '"'),
  );
}

function normalizeQuery(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function versionFromDigits(digits: string): string {
  if (/^\d{6}$/.test(digits)) {
    return `${digits.slice(0, 2)}.${digits.slice(2, 4)}.${digits.slice(4, 5)}.${digits.slice(5, 6)}`;
  }

  if (/^\d{4}$/.test(digits)) {
    return `${digits.slice(0, 1)}.${digits.slice(1, 2)}.${digits.slice(2, 3)}.${digits.slice(3, 4)}`;
  }

  return digits;
}

function shortenVersion(version: string): string {
  const parts = version.split(".");
  while (parts.length > 2 && parts[parts.length - 1] === "0") {
    parts.pop();
  }
  return parts.join(".");
}

function versionAliases(version: VersionLink): string[] {
  const guidesFile = path.posix.basename(new URL(version.guidesPageUrl).pathname, ".html");
  return Array.from(
    new Set(
      [
        version.version,
        version.versionShort,
        version.versionKey,
        guidesFile,
        `${guidesFile}.html`,
      ]
        .map((entry) => normalizeQuery(entry))
        .filter(Boolean),
    ),
  );
}

function chooseFetch(fetchImpl?: typeof fetch): typeof fetch {
  if (fetchImpl) {
    return fetchImpl;
  }

  if (typeof fetch !== "function") {
    throw new HandledError(
      "DOCS_FETCH_UNAVAILABLE",
      "Global fetch is not available in this Node runtime.",
    );
  }

  return fetch;
}

async function fetchText(url: string, fetchImpl?: typeof fetch): Promise<string> {
  const response = await chooseFetch(fetchImpl)(url, {
    headers: {
      accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    },
  });

  if (!response.ok) {
    throw new HandledError(
      "DOCS_FETCH_FAILED",
      `Failed to fetch Oracle NMS documentation index from ${url} (HTTP ${response.status}).`,
      { url, httpStatus: response.status },
    );
  }

  return await response.text();
}

async function fetchBinary(url: string, fetchImpl?: typeof fetch): Promise<Buffer> {
  const response = await chooseFetch(fetchImpl)(url, {
    headers: {
      accept: "application/pdf,application/octet-stream;q=0.9,*/*;q=0.8",
    },
  });

  if (!response.ok) {
    throw new HandledError(
      "DOCS_FETCH_FAILED",
      `Failed to download Oracle NMS PDF from ${url} (HTTP ${response.status}).`,
      { url, httpStatus: response.status },
    );
  }

  return Buffer.from(await response.arrayBuffer());
}

function parseVersionLinks(html: string, booksUrl: string): VersionLink[] {
  const versions: VersionLink[] = [];
  const seen = new Set<string>();

  for (const match of html.matchAll(LINK_PATTERN)) {
    const href = match[1] ?? "";
    const text = stripHtml(match[2] ?? "");
    const guidesMatch = href.match(VERSION_GUIDES_PATH_PATTERN);
    if (!guidesMatch) {
      continue;
    }

    const guidesPageUrl = new URL(href, booksUrl).toString();
    const versionKey = guidesMatch[1]
      .replace(/^nms_/i, "")
      .replace(/_guides\.html$/i, "")
      .toLowerCase();
    if (seen.has(guidesPageUrl)) {
      continue;
    }

    const versionLabel = normalizeWhitespace(text.replace(/\bguides\b/i, "")) || versionFromDigits(versionKey);
    versions.push({
      version: versionLabel,
      versionShort: shortenVersion(versionLabel),
      versionKey,
      guidesPageUrl,
    });
    seen.add(guidesPageUrl);
  }

  if (versions.length === 0) {
    throw new HandledError(
      "DOCS_PARSE_FAILED",
      `Could not find any Oracle NMS guide versions on ${booksUrl}.`,
      { url: booksUrl },
    );
  }

  return versions;
}

function parseGuideEntries(html: string, guidesPageUrl: string): RawGuideEntry[] {
  const jsonMatch = html.match(GUIDE_JSON_PATTERN);
  if (!jsonMatch?.[1]) {
    throw new HandledError(
      "DOCS_PARSE_FAILED",
      `Could not find guide metadata on ${guidesPageUrl}.`,
      { url: guidesPageUrl },
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonMatch[1]);
  } catch (error) {
    throw new HandledError(
      "DOCS_PARSE_FAILED",
      `Failed to parse guide metadata on ${guidesPageUrl}.`,
      { url: guidesPageUrl, parseError: error instanceof Error ? error.message : String(error) },
    );
  }

  if (!Array.isArray(parsed)) {
    throw new HandledError(
      "DOCS_PARSE_FAILED",
      `Guide metadata on ${guidesPageUrl} was not an array.`,
      { url: guidesPageUrl },
    );
  }

  return parsed as RawGuideEntry[];
}

function buildCachePath(cacheDir: string, version: VersionLink, pdfFileName: string): string {
  return path.resolve(cacheDir, version.versionKey, pdfFileName);
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    const fileStat = await stat(filePath);
    return fileStat.isFile();
  } catch {
    return false;
  }
}

async function loadGuidesForVersion(
  version: VersionLink,
  options: FetchOptions,
): Promise<NmsVersionSummary> {
  const html = await fetchText(version.guidesPageUrl, options.fetchImpl);
  const rawGuides = parseGuideEntries(html, version.guidesPageUrl);

  const guides: NmsGuideSummary[] = [];
  for (const entry of rawGuides) {
    if (!entry.title || !entry.pdf || !entry.html) {
      continue;
    }

    const pdfUrl = new URL(entry.pdf, version.guidesPageUrl).toString();
    const htmlUrl = new URL(entry.html, version.guidesPageUrl).toString();
    const slug =
      path.posix.basename(path.posix.dirname(new URL(htmlUrl).pathname)) ||
      path.posix.basename(new URL(pdfUrl).pathname, ".pdf");
    const pdfFileName = path.posix.basename(new URL(pdfUrl).pathname);
    const localPdfPath = buildCachePath(
      options.cacheDir ?? DEFAULT_NMS_CACHE_DIR,
      version,
      pdfFileName,
    );
    const cached = await fileExists(localPdfPath);

    guides.push({
      title: normalizeWhitespace(entry.title),
      slug,
      description: normalizeWhitespace(entry.description ?? ""),
      category: normalizeWhitespace(entry.category ?? "Other"),
      pdfUrl,
      htmlUrl,
      pdfFileName,
      cached,
      cachedPdfPath: cached ? localPdfPath : null,
    });
  }

  return {
    version: version.version,
    versionShort: version.versionShort,
    versionKey: version.versionKey,
    guidesPageUrl: version.guidesPageUrl,
    guideCount: guides.length,
    guides,
  };
}

function matchVersion(versions: VersionLink[], versionQuery?: string): VersionLink[] {
  if (!versionQuery) {
    return versions;
  }

  const normalizedQuery = normalizeQuery(versionQuery);
  const exactMatches = versions.filter((version) => versionAliases(version).includes(normalizedQuery));
  if (exactMatches.length > 0) {
    return exactMatches;
  }

  const partialMatches = versions.filter((version) =>
    versionAliases(version).some((alias) => alias.includes(normalizedQuery) || normalizedQuery.includes(alias)),
  );
  if (partialMatches.length > 0) {
    return partialMatches;
  }

  throw new HandledError(
    "DOCS_VERSION_NOT_FOUND",
    `Could not find an Oracle NMS documentation version matching "${versionQuery}".`,
    {
      requestedVersion: versionQuery,
      availableVersions: versions.map((version) => version.version),
    },
  );
}

function guideAliases(guide: NmsGuideSummary): string[] {
  return Array.from(
    new Set(
      [guide.title, guide.slug, guide.pdfFileName]
        .map((entry) => normalizeQuery(entry))
        .filter(Boolean),
    ),
  );
}

function matchGuide(guides: NmsGuideSummary[], guideQuery: string): NmsGuideSummary {
  const normalizedQuery = normalizeQuery(guideQuery);
  const exactMatches = guides.filter((guide) => guideAliases(guide).includes(normalizedQuery));
  if (exactMatches.length === 1) {
    return exactMatches[0] ?? guides[0];
  }

  if (exactMatches.length > 1) {
    throw new HandledError(
      "DOCS_GUIDE_AMBIGUOUS",
      `Multiple Oracle NMS guides matched "${guideQuery}".`,
      { requestedGuide: guideQuery, candidates: exactMatches.map((guide) => guide.title) },
    );
  }

  const partialMatches = guides.filter((guide) =>
    guideAliases(guide).some((alias) => alias.includes(normalizedQuery) || normalizedQuery.includes(alias)),
  );
  if (partialMatches.length === 1) {
    return partialMatches[0] ?? guides[0];
  }

  if (partialMatches.length > 1) {
    throw new HandledError(
      "DOCS_GUIDE_AMBIGUOUS",
      `Multiple Oracle NMS guides matched "${guideQuery}".`,
      { requestedGuide: guideQuery, candidates: partialMatches.map((guide) => guide.title) },
    );
  }

  throw new HandledError(
    "DOCS_GUIDE_NOT_FOUND",
    `Could not find an Oracle NMS guide matching "${guideQuery}".`,
    {
      requestedGuide: guideQuery,
      availableGuides: guides.map((guide) => guide.title),
    },
  );
}

async function loadVersionLinks(options: FetchOptions): Promise<VersionLink[]> {
  const booksUrl = options.booksUrl ?? DEFAULT_NMS_BOOKS_URL;
  const html = await fetchText(booksUrl, options.fetchImpl);
  return parseVersionLinks(html, booksUrl);
}

export async function listNmsGuides(
  options: GuideMatchOptions = {},
): Promise<ListNmsGuidesResult> {
  const booksUrl = options.booksUrl ?? DEFAULT_NMS_BOOKS_URL;
  const cacheDir = path.resolve(options.cacheDir ?? DEFAULT_NMS_CACHE_DIR);
  const versions = matchVersion(await loadVersionLinks({ ...options, booksUrl }), options.versionQuery);
  const populatedVersions = await Promise.all(
    versions.map((version) => loadGuidesForVersion(version, { ...options, cacheDir })),
  );

  return {
    sourceBooksUrl: booksUrl,
    cacheDir,
    versionCount: populatedVersions.length,
    versions: populatedVersions,
  };
}

export async function resolveNmsGuidePdf(
  options: ResolveGuideOptions,
): Promise<ResolveNmsGuidePdfResult> {
  const booksUrl = options.booksUrl ?? DEFAULT_NMS_BOOKS_URL;
  const cacheDir = path.resolve(options.cacheDir ?? DEFAULT_NMS_CACHE_DIR);
  const versions = matchVersion(await loadVersionLinks({ ...options, booksUrl }), options.versionQuery);

  if (versions.length !== 1) {
    throw new HandledError(
      "DOCS_VERSION_AMBIGUOUS",
      `The version query "${options.versionQuery ?? ""}" matched multiple Oracle NMS documentation versions.`,
      { requestedVersion: options.versionQuery ?? null, matches: versions.map((version) => version.version) },
    );
  }

  const selectedVersion = versions[0];
  if (!selectedVersion) {
    throw new HandledError(
      "DOCS_VERSION_NOT_FOUND",
      "No Oracle NMS documentation versions matched the requested query.",
      { requestedVersion: options.versionQuery ?? null },
    );
  }
  const versionSummary = await loadGuidesForVersion(selectedVersion, {
    ...options,
    cacheDir,
  });
  const guide = matchGuide(versionSummary.guides, options.guideQuery);
  const pdfPath = buildCachePath(cacheDir, selectedVersion, guide.pdfFileName);
  const alreadyCached = await fileExists(pdfPath);

  let buffer: Buffer | undefined;
  let downloaded = false;
  if (!alreadyCached || options.refresh) {
    buffer = await fetchBinary(guide.pdfUrl, options.fetchImpl);
    await mkdir(path.dirname(pdfPath), { recursive: true });
    await writeFile(pdfPath, buffer);
    downloaded = true;
  }

  const fileStat = await stat(pdfPath);
  const finalBuffer = buffer ?? (await readFile(pdfPath));
  const contentSha256 = createHash("sha256").update(finalBuffer).digest("hex");

  return {
    sourceBooksUrl: booksUrl,
    sourceGuidesPageUrl: versionSummary.guidesPageUrl,
    cacheDir,
    version: versionSummary.version,
    versionShort: versionSummary.versionShort,
    versionKey: versionSummary.versionKey,
    guideTitle: guide.title,
    guideSlug: guide.slug,
    pdfUrl: guide.pdfUrl,
    htmlUrl: guide.htmlUrl,
    pdfFileName: guide.pdfFileName,
    cached: !downloaded,
    downloaded,
    pdfPath,
    fileSizeBytes: fileStat.size,
    contentSha256,
  };
}
