# Third-party files served from /static/vendor/

The dashboard loads no script, style or font from another host. The files
below are copies of a published package, unchanged.

## jsvectormap 1.5.3

World map on the DNS page (Infrastructure view).

- Package: `jsvectormap` (npm), version 1.5.3
- Licence: MIT
- Source: `https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/`

| File | Source path below `dist/` | SHA-256 |
|---|---|---|
| `jsvectormap/jsvectormap.min.js` | `js/jsvectormap.min.js` | `fedd67376f79e814fcebd13a1f8575767b745f9a404073f2b658bed674d99b66` |
| `jsvectormap/jsvectormap.min.css` | `css/jsvectormap.min.css` | `fae18b26699328ea81afed84e8a0d8b3f351b07c5290e35714750bd1fcb63bfe` |
| `jsvectormap/world.js` | `maps/world.js` | `5cfa4f699954f12fc759fec564b02770b83648090ff127144c823cf71f43de56` |

Check the copies: `shasum -a 256 jsvectormap/*` in this directory.

To update: download the three files of the new version from the same paths,
replace the version and the hashes here, and change the version in the
application so the pages ask for the new files (static files are requested
with `?v=<application version>` and cached for a year under that URL).
