import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { listNmsGuides, resolveNmsGuidePdf } from "../dist/nms-docs.js";

const BOOKS_URL = "https://docs.example.test/books.html";
const GUIDES_2512_URL = "https://docs.example.test/nms_251200_guides.html";
const GUIDES_2602_URL = "https://docs.example.test/nms_2602_guides.html";
const PDF_2512_URL = "https://docs.example.test/251200/nms-installation-guide/G49134.pdf";

const BOOKS_HTML = `
<!DOCTYPE html>
<html>
  <body>
    <a href="nms_251200_guides.html">25.12.0.0 Guides</a>
    <a href="nms_2602_guides.html">2.6.0.2 Guides</a>
  </body>
</html>`;

const GUIDES_2512_HTML = `
<!DOCTYPE html>
<html>
  <body>
    <script type="application/json" id="book-data">
      [
        {
          "title":"Network Management System Installation Guide",
          "description":"Install and upgrade guidance.",
          "pdf":"251200/nms-installation-guide/G49134.pdf",
          "html":"251200/nms-installation-guide/index.html",
          "category":"Other"
        },
        {
          "title":"Network Management System User Guide",
          "description":"User tasks.",
          "pdf":"251200/nms-user-guide/G49139.pdf",
          "html":"251200/nms-user-guide/index.html",
          "category":"Other"
        }
      ]
    </script>
  </body>
</html>`;

const GUIDES_2602_HTML = `
<!DOCTYPE html>
<html>
  <body>
    <script type="application/json" id="book-data">
      [
        {
          "title":"Network Management System Release Notes",
          "description":"Legacy release notes.",
          "pdf":"2602/nms-release-notes/G00001.pdf",
          "html":"2602/nms-release-notes/index.html",
          "category":"Other"
        }
      ]
    </script>
  </body>
</html>`;

function createFetchStub() {
  let pdfFetchCount = 0;
  const fetchStub = async (url) => {
    switch (String(url)) {
      case BOOKS_URL:
        return new Response(BOOKS_HTML, { status: 200 });
      case GUIDES_2512_URL:
        return new Response(GUIDES_2512_HTML, { status: 200 });
      case GUIDES_2602_URL:
        return new Response(GUIDES_2602_HTML, { status: 200 });
      case PDF_2512_URL:
        pdfFetchCount += 1;
        return new Response(Buffer.from("%PDF-1.4 test pdf"), {
          status: 200,
          headers: {
            "content-type": "application/pdf",
          },
        });
      default:
        return new Response("Not Found", { status: 404 });
    }
  };

  return {
    fetchStub,
    getPdfFetchCount: () => pdfFetchCount,
  };
}

test("lists Oracle NMS versions and cached local paths", async (t) => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), "nms-docs-list-"));
  t.after(async () => {
    await rm(cacheDir, { recursive: true, force: true });
  });

  const cachedPdfPath = path.join(cacheDir, "251200", "G49134.pdf");
  await mkdir(path.dirname(cachedPdfPath), { recursive: true });
  await writeFile(cachedPdfPath, Buffer.from("cached"));

  const { fetchStub } = createFetchStub();
  const result = await listNmsGuides({
    booksUrl: BOOKS_URL,
    cacheDir,
    versionQuery: "25.12",
    fetchImpl: fetchStub,
  });

  assert.equal(result.versionCount, 1);
  assert.equal(result.versions[0]?.version, "25.12.0.0");
  assert.equal(result.versions[0]?.versionShort, "25.12");
  assert.equal(result.versions[0]?.guideCount, 2);
  assert.equal(result.versions[0]?.guides[0]?.cached, true);
  assert.equal(result.versions[0]?.guides[0]?.cachedPdfPath, cachedPdfPath);
  assert.equal(result.versions[0]?.guides[1]?.cached, false);
});

test("downloads and then reuses a cached Oracle NMS guide PDF", async (t) => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), "nms-docs-get-"));
  t.after(async () => {
    await rm(cacheDir, { recursive: true, force: true });
  });

  const { fetchStub, getPdfFetchCount } = createFetchStub();
  const downloaded = await resolveNmsGuidePdf({
    booksUrl: BOOKS_URL,
    cacheDir,
    versionQuery: "251200",
    guideQuery: "installation guide",
    fetchImpl: fetchStub,
  });

  assert.equal(downloaded.downloaded, true);
  assert.equal(downloaded.cached, false);
  assert.equal(downloaded.versionShort, "25.12");
  assert.match(downloaded.pdfPath, /G49134\.pdf$/);
  assert.equal(getPdfFetchCount(), 1);
  assert.equal(
    (await readFile(downloaded.pdfPath, "utf8")).startsWith("%PDF-1.4"),
    true,
  );

  const reused = await resolveNmsGuidePdf({
    booksUrl: BOOKS_URL,
    cacheDir,
    versionQuery: "25.12.0.0",
    guideQuery: "nms-installation-guide",
    fetchImpl: fetchStub,
  });

  assert.equal(reused.downloaded, false);
  assert.equal(reused.cached, true);
  assert.equal(reused.pdfPath, downloaded.pdfPath);
  assert.equal(getPdfFetchCount(), 1);
});
